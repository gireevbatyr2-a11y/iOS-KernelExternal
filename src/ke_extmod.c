//
//  ke_extmod.c — extmod statistics: self-calibration and zeroing
//
//  In XNU (iOS 16+; same counters exist in later 15.x builds used by
//  Dopamine-supported firmware) every task carries:
//
//    struct vm_extmod_statistics {           // osfmk/mach/vm_statistics.h
//        int64_t task_for_pid_count;         // +8 each when this task is target of task_for_pid
//        int64_t task_for_pid_caller_count;  // +8 each when this task CALLS task_for_pid
//        int64_t thread_creation_count;
//        int64_t thread_creation_caller_count;
//        int64_t thread_set_state_count;
//        int64_t thread_set_state_caller_count;
//    } __attribute__((aligned(8)));          // 0x30 bytes, inside struct task
//
//  extmod_statistics_incr_task_for_pid() increments both caller and target.
//  Counters surface in crash reports (extMods caller/system/targeted) and
//  are an anti-tamper/forensics signal.
//
//  The offset of extmod_statistics within struct task varies between builds,
//  so instead of a hardcoded table we self-calibrate at runtime:
//    1. snapshot the caller task struct,
//    2. perform N task_for_pid() calls on a known target,
//    3. snapshot again — the only 8-aligned 0x30 window where
//       caller_count went +N (target count slot untouched) in the caller
//       struct and count went +N (caller slot untouched) in the target
//       struct at the same offset IS extmod_statistics.
//
#include "ke_internal.h"

#define KE_EXTMOD_SIZE 0x30
#define KE_TASK_SNAPSHOT_SIZE 0x800
#define KE_TFP_CALLS_PER_ROUND 2

static int64_t g_extmodOffset = -1;

static int keReadTaskWindow(uint64_t taskKaddr, uint64_t *buf, size_t qwords)
{
    return keKreadBuf(taskKaddr, buf, qwords * sizeof(uint64_t));
}

// find offset (in u64 slots) where delta == expected, with all other
// slots in the 6-slot window unchanged; returns slot index or -1
static int keFindDeltaSlot(const uint64_t *before, const uint64_t *after, size_t qwords, int64_t delta, int slotInWindow)
{
    for (size_t i = 0; i + 6 <= qwords; i++) {
        if ((i % 1) != 0) continue; // every slot is a candidate; alignment check below
        if (((i * sizeof(uint64_t)) % 8) != 0) continue;
        bool ok = true;
        for (size_t w = 0; w < 6 && ok; w++) {
            int64_t d = (int64_t)(after[i + w] - before[i + w]);
            if (w == (size_t)slotInWindow) {
                if (d != delta) ok = false;
            } else {
                if (d != 0) ok = false;
            }
        }
        if (ok) return (int)i;
    }
    return -1;
}

int keCalibrateExtmodOffset(void)
{
    if (g_extmodOffset >= 0) return 0;

    if (!keIsInitialized()) return KE_ERR_NOT_INITIALIZED;

    pid_t selfPid = getpid();

    // target: our own parent (always exists, never ourselves)
    pid_t targetPid = getppid();
    if (targetPid <= 0 || targetPid == selfPid) return KE_ERR_CALIBRATION_FAILED;

    uint64_t selfTask = keTaskOfPid(selfPid);
    uint64_t targetTask = keTaskOfPid(targetPid);
    if (!selfTask || !targetTask || selfTask == targetTask) return KE_ERR_CALIBRATION_FAILED;

    static uint64_t selfBefore[KE_TASK_SNAPSHOT_SIZE / 8];
    static uint64_t selfAfter[KE_TASK_SNAPSHOT_SIZE / 8];
    static uint64_t targetBefore[KE_TASK_SNAPSHOT_SIZE / 8];
    static uint64_t targetAfter[KE_TASK_SNAPSHOT_SIZE / 8];

    if (keReadTaskWindow(selfTask, selfBefore, KE_TASK_SNAPSHOT_SIZE / 8) != 0) return KE_ERR_CALIBRATION_FAILED;
    if (keReadTaskWindow(targetTask, targetBefore, KE_TASK_SNAPSHOT_SIZE / 8) != 0) return KE_ERR_CALIBRATION_FAILED;

    for (int round = 0; round < KE_TFP_CALLS_PER_ROUND; round++) {
        mach_port_t t = MACH_PORT_NULL;
        if (task_for_pid(mach_task_self(), targetPid, &t) != KERN_SUCCESS) return KE_ERR_TFP_FAILED;
        if (t != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), t);
    }

    if (keReadTaskWindow(selfTask, selfAfter, KE_TASK_SNAPSHOT_SIZE / 8) != 0) return KE_ERR_CALIBRATION_FAILED;
    if (keReadTaskWindow(targetTask, targetAfter, KE_TASK_SNAPSHOT_SIZE / 8) != 0) return KE_ERR_CALIBRATION_FAILED;

    // caller struct: slot 1 (task_for_pid_caller_count) went +N
    int selfSlot = keFindDeltaSlot(selfBefore, selfAfter, KE_TASK_SNAPSHOT_SIZE / 8, KE_TFP_CALLS_PER_ROUND, 1);
    // target struct: slot 0 (task_for_pid_count) went +N
    int targetSlot = keFindDeltaSlot(targetBefore, targetAfter, KE_TASK_SNAPSHOT_SIZE / 8, KE_TFP_CALLS_PER_ROUND, 0);

    if (selfSlot < 0 || targetSlot < 0) return KE_ERR_CALIBRATION_FAILED;

    // cross-check: both structs must agree on the same byte offset
    int64_t selfOff = (int64_t)(selfSlot * sizeof(uint64_t));
    int64_t targetOff = (int64_t)(targetSlot * sizeof(uint64_t));
    if (selfOff != targetOff) {
        // re-run with more calls to disambiguate
        g_extmodOffset = -1;
        return KE_ERR_CALIBRATION_FAILED;
    }

    g_extmodOffset = selfOff;
    KE_LOG("extmod_statistics offset calibrated: 0x%llx", g_extmodOffset);
    return 0;
}

int64_t keGetExtmodOffset(void)
{
    return g_extmodOffset;
}

void keInvalidateExtmodCalibration(void)
{
    g_extmodOffset = -1;
}

int keGetExtmodOfTask(uint64_t taskKaddr, KEExtmodCounters *out)
{
    if (!out) return KE_ERR_INVALID_ARGUMENT;
    if (g_extmodOffset < 0) {
        int r = keCalibrateExtmodOffset();
        if (r != 0) return r;
    }
    uint64_t window[6] = { 0 };
    int r = keKreadBuf(taskKaddr + g_extmodOffset, window, KE_EXTMOD_SIZE);
    if (r != 0) return r;
    out->taskForPidCount = (int64_t)window[0];
    out->taskForPidCallerCount = (int64_t)window[1];
    out->threadCreationCount = (int64_t)window[2];
    out->threadCreationCallerCount = (int64_t)window[3];
    out->threadSetStateCount = (int64_t)window[4];
    out->threadSetStateCallerCount = (int64_t)window[5];
    return 0;
}

int keGetExtmodOfPid(pid_t pid, KEExtmodCounters *out)
{
    uint64_t task = keTaskOfPid(pid);
    if (!task) return KE_ERR_NO_KERNEL_MEMORY;
    return keGetExtmodOfTask(task, out);
}

int keZeroExtmodOfTask(uint64_t taskKaddr)
{
    if (g_extmodOffset < 0) {
        int r = keCalibrateExtmodOffset();
        if (r != 0) return r;
    }
    static const uint64_t zeros[6] = { 0 };
    return keKwriteBuf(taskKaddr + g_extmodOffset, zeros, KE_EXTMOD_SIZE);
}

int keZeroExtmodOfPid(pid_t pid)
{
    uint64_t task = keTaskOfPid(pid);
    if (!task) return KE_ERR_NO_KERNEL_MEMORY;
    return keZeroExtmodOfTask(task);
}

int keZeroExtmodSelf(void)
{
    return keZeroExtmodOfPid(getpid());
}


// Native read via TASK_EXTMOD_INFO (mach/task_info.h, iOS 16+ SDK) — needs
// the com.apple.system-task-ports(-read) entitlement for other tasks, works
// entitlement-free for the calling task itself.
kern_return_t keGetExtmodFromPort(mach_port_t taskPort, KEExtmodCounters *out)
{
    if (!out) return KERN_INVALID_ARGUMENT;
    task_extmod_info_data_t info = { 0 };
    mach_msg_type_number_t count = TASK_EXTMOD_INFO_COUNT;
    kern_return_t kr = task_info(taskPort, TASK_EXTMOD_INFO, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS) return kr;
    out->taskForPidCount           = info.task_extmod_statistics.task_for_pid_count;
    out->taskForPidCallerCount     = info.task_extmod_statistics.task_for_pid_caller_count;
    out->threadCreationCount       = info.task_extmod_statistics.thread_creation_count;
    out->threadCreationCallerCount = info.task_extmod_statistics.thread_creation_caller_count;
    out->threadSetStateCount       = info.task_extmod_statistics.thread_set_state_count;
    out->threadSetStateCallerCount = info.task_extmod_statistics.thread_set_state_caller_count;
    return KERN_SUCCESS;
}

int keGetExtmodNative(pid_t pid, KEExtmodCounters *out)
{
    mach_port_t taskPort = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &taskPort);
    if (kr != KERN_SUCCESS) return kr;
    kr = keGetExtmodFromPort(taskPort, out);
    mach_port_deallocate(mach_task_self(), taskPort);
    return kr;
}

// Native TASK_EXTMOD_INFO (flavor 19) read via a task port — needs the
// com.apple.system-task-ports entitlement, no kernel r/w involved.
#ifndef TASK_EXTMOD_INFO
#define TASK_EXTMOD_INFO 19
typedef struct task_extmod_info {
    vm_extmod_statistics_data_t task_extmod_statistics;
    mach_msg_type_number_t reserved[10];
} task_extmod_info_data_t;
#define TASK_EXTMOD_INFO_COUNT (sizeof(task_extmod_info_data_t) / sizeof(natural_t))
#endif

kern_return_t keGetExtmodFromPort(mach_port_t taskPort, KEExtmodCounters *out)
{
    if (!out) return KERN_INVALID_ARGUMENT;
    task_extmod_info_data_t info = { 0 };
    mach_msg_type_number_t count = TASK_EXTMOD_INFO_COUNT;
    kern_return_t kr = task_info(taskPort, TASK_EXTMOD_INFO, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS) return kr;
    out->taskForPidCount = (int64_t)info.task_extmod_statistics.task_for_pid_count;
    out->taskForPidCallerCount = (int64_t)info.task_extmod_statistics.task_for_pid_caller_count;
    out->threadCreationCount = (int64_t)info.task_extmod_statistics.thread_creation_count;
    out->threadCreationCallerCount = (int64_t)info.task_extmod_statistics.thread_creation_caller_count;
    out->threadSetStateCount = (int64_t)info.task_extmod_statistics.thread_set_state_count;
    out->threadSetStateCallerCount = (int64_t)info.task_extmod_statistics.thread_set_state_caller_count;
    return KERN_SUCCESS;
}

int keGetExtmodNative(pid_t pid, KEExtmodCounters *out)
{
    if (!out) return KE_ERR_INVALID_ARGUMENT;
    mach_port_t taskPort = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &taskPort) != KERN_SUCCESS) return KE_ERR_TFP_FAILED;
    kern_return_t kr = keGetExtmodFromPort(taskPort, out);
    if (taskPort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), taskPort);
    return (kr == KERN_SUCCESS) ? 0 : KE_ERR_TFP_FAILED;
}

kern_return_t keGetExtmodFromPort(mach_port_t taskPort, KEExtmodCounters *out)
{
    if (!out) return KERN_INVALID_ARGUMENT;
    task_extmod_info_data_t info = { 0 };
    mach_msg_type_number_t count = TASK_EXTMOD_INFO_COUNT;
    kern_return_t kr = task_info(taskPort, TASK_EXTMOD_INFO, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS) return kr;
    out->taskForPidCount           = info.task_extmod_statistics.task_for_pid_count;
    out->taskForPidCallerCount     = info.task_extmod_statistics.task_for_pid_caller_count;
    out->threadCreationCount       = info.task_extmod_statistics.thread_creation_count;
    out->threadCreationCallerCount = info.task_extmod_statistics.thread_creation_caller_count;
    out->threadSetStateCount       = info.task_extmod_statistics.thread_set_state_count;
    out->threadSetStateCallerCount = info.task_extmod_statistics.thread_set_state_caller_count;
    return KERN_SUCCESS;
}

int keGetExtmodNative(pid_t pid, KEExtmodCounters *out)
{
    mach_port_t taskPort = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &taskPort) != KERN_SUCCESS) {
        return KE_ERR_TFP_FAILED;
    }
    kern_return_t kr = keGetExtmodFromPort(taskPort, out);
    mach_port_deallocate(mach_task_self(), taskPort);
    return (kr == KERN_SUCCESS) ? KE_OK : KE_ERR_TFP_FAILED;
}
