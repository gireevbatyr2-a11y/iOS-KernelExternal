//
//  ke_proc.c — kernel proc/task discovery
//
//  Primary path: mach_port_kobject on a task send right returns the kernel
//  address of the backing task object — no offsets required.
//  Fallback path: allproc list walk from the per-build offsets table.
//
#include "ke_internal.h"

static bool keKaddrLooksSane(uint64_t kaddr)
{
    return (kaddr >= 0xfffffe0000000000ULL && kaddr <= 0xfffffffffff00000ULL);
}

uint64_t keTaskOfTaskPort(mach_port_t taskPort)
{
    natural_t type = 0;
    mach_vm_address_t kaddr = 0;
    kern_return_t kr = mach_port_kobject(mach_task_self(), taskPort, &type, &kaddr);
    if (kr != KERN_SUCCESS) return 0;
    if (!keKaddrLooksSane(kaddr)) return 0;
    return kaddr;
}

// allproc walk — requires offsets table entry (allproc) for the running build
uint64_t keTaskOfPidAllproc(pid_t pid, uint64_t *procOut)
{
    const KEBuildOffsets *o = keOffsetsForCurrentBuild();
    if (!o->allproc) return 0;

    uint64_t proc = 0;
    if (keKread64(o->allproc, &proc) != 0) return 0;
    for (int i = 0; i < 4096 && proc; i++) {
        int32_t curPid = 0;
        if (keKreadBuf(proc + o->procPid, &curPid, sizeof(curPid)) != 0) return 0;
        if (curPid == pid) {
            uint64_t task = 0;
            if (o->procTask) {
                if (keKread64(proc + o->procTask, &task) != 0) return 0;
            } else {
                task = proc + o->procObjectSize;
            }
            if (procOut) *procOut = proc;
            return task;
        }
        if (keKread64(proc + o->procListNext, &proc) != 0) return 0;
    }
    return 0;
}

// Backward walk from kernel_proc (kfd runtime path — no allproc symbol needed).
// kernel_proc is proc0, the last entry of allproc; p_list.le_prev chains toward
// the head of the list. Stops at proc0's pid==0 anchor.
uint64_t keTaskOfPidKernelProc(pid_t pid, uint64_t *procOut)
{
    if (!gKeKfdKernelProc) return 0;

    const uint64_t pidOff = gKeRuntimeProcPid;
    const uint64_t prevOff = 0x8;
    const uint64_t procObjectSize = gKeRuntimeProcObjectSize;

    uint64_t proc = gKeKfdKernelProc;
    for (int i = 0; i < 4096; i++) {
        int32_t curPid = 0;
        if (keKreadBuf(proc + pidOff, &curPid, sizeof(curPid)) != 0) return 0;
        if (curPid == pid && pid != 0) {
            uint64_t task = 0;
            if (gKeRuntimeProcTask) {
                if (keKread64(proc + gKeRuntimeProcTask, &task) != 0) return 0;
            } else {
                task = proc + procObjectSize;
            }
            if (procOut) *procOut = proc;
            return task;
        }
        if (curPid == 0) break;

        uint64_t prev = 0;
        if (keKread64(proc + prevOff, &prev) != 0) return 0;
        if (!prev) break;
        proc = prev;
    }
    return 0;
}

uint64_t keTaskOfPid(pid_t pid)
{
    if (!keIsInitialized()) return 0;

    mach_port_t taskPort = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &taskPort) == KERN_SUCCESS && taskPort != MACH_PORT_NULL) {
        uint64_t taskKaddr = keTaskOfTaskPort(taskPort);
        mach_port_deallocate(mach_task_self(), taskPort);
        if (taskKaddr) return taskKaddr;
    }
    uint64_t task = keTaskOfPidAllproc(pid, NULL);
    if (task) return task;
    return keTaskOfPidKernelProc(pid, NULL);
}

uint64_t keProcOfPid(pid_t pid)
{
    if (!keIsInitialized()) return 0;
    uint64_t proc = 0;
    keTaskOfPidAllproc(pid, &proc);
    if (!proc) keTaskOfPidKernelProc(pid, &proc);
    return proc;
}
