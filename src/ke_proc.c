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

// Serotonin-style PAC un-signing: T1SZ_BOOT is 17 for A16/M1/M2-class chips
// and 25 for everything else. List pointers read from kernel memory are
// PAC-signed on arm64e and must be normalized before use.
static uint64_t keT1szBootCache = 0;

static uint64_t keT1szBoot(void)
{
    if (keT1szBootCache) return keT1szBootCache;
    char ver[512] = {0};
    size_t size = sizeof(ver);
    if (sysctlbyname("kern.version", ver, &size, NULL, 0) == 0
        && (strstr(ver, "T8120") || strstr(ver, "T8103") || strstr(ver, "T8112"))) {
        keT1szBootCache = 17;
    } else {
        keT1szBootCache = 25;
    }
    return keT1szBootCache;
}

static uint64_t keUnsignKaddr(uint64_t kaddr)
{
    if (!(kaddr & (1ULL << 55))) {
        return kaddr;
    }
    return kaddr | ~((1ULL << (64 - keT1szBoot())) - 1ULL);
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

// proc -> task resolution, works for both layouts:
//   iOS 15 (kfd):   task embedded in proc at a fixed offset
//   iOS 16+ (lara): proc->p_ro (PAC'd) -> proc_ro->pr_task
uint64_t keTaskOfProcKaddr(uint64_t proc)
{
    if (!proc) return 0;
    if (gKeRuntimeProcProcRo) {
        uint64_t ro = 0;
        if (keKread64(proc + gKeRuntimeProcProcRo, &ro) != 0) return 0;
        ro = keUnsignKaddr(ro);
        uint64_t task = 0;
        if (keKread64(ro + gKeRuntimeProcTask, &task) != 0) return 0;
        return keUnsignKaddr(task);
    }
    if (gKeRuntimeProcTask) {
        uint64_t task = 0;
        if (keKread64(proc + gKeRuntimeProcTask, &task) != 0) return 0;
        return keUnsignKaddr(task);
    }
    return 0;
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
            task = keTaskOfProcKaddr(proc);
            if (!task) task = proc + o->procObjectSize;
            if (procOut) *procOut = proc;
            return task;
        }
        uint64_t next = 0;
        if (keKread64(proc + o->procListNext, &next) != 0) return 0;
        next = keUnsignKaddr(next);
        if (!next || next == proc) return 0;
        proc = next;
    }
    return 0;
}

// Forward walk from proc 0 (kfd runtime path — no allproc symbol needed).
// gKeKfdKernelProc is proc 0, the head of allproc; iterating le_next covers
// every process, including ones created after ours. The walk ends at the
// list head address, which is exactly proc0's p_list.le_prev value.
uint64_t keTaskOfPidKernelProc(pid_t pid, uint64_t *procOut)
{
    if (!gKeKfdKernelProc || !gKeRuntimeProcPid) return 0;

    const uint64_t pidOff = gKeRuntimeProcPid;
    const uint64_t procObjectSize = gKeRuntimeProcObjectSize;

    uint64_t head = 0;
    if (keKread64(gKeKfdKernelProc + 0x8, &head) != 0) return 0;
    head = keUnsignKaddr(head);

    uint64_t proc = gKeKfdKernelProc;
    for (int i = 0; i < 8192; i++) {
        int32_t curPid = 0;
        if (keKreadBuf(proc + pidOff, &curPid, sizeof(curPid)) != 0) return 0;
        if (curPid == pid && pid != 0) {
            uint64_t task = 0;
            task = keTaskOfProcKaddr(proc);
            if (!task) task = proc + procObjectSize;
            if (procOut) *procOut = proc;
            return task;
        }

        uint64_t next = 0;
        if (keKread64(proc + 0x0, &next) != 0) return 0;
        next = keUnsignKaddr(next);
        if (!next || next == head || next == proc) return 0;
        proc = next;
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
