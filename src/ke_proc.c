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

uint64_t keTaskOfPid(pid_t pid)
{
    if (!keIsInitialized()) return 0;

    mach_port_t taskPort = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &taskPort) == KERN_SUCCESS && taskPort != MACH_PORT_NULL) {
        uint64_t taskKaddr = keTaskOfTaskPort(taskPort);
        mach_port_deallocate(mach_task_self(), taskPort);
        if (taskKaddr) return taskKaddr;
    }
    return keTaskOfPidAllproc(pid, NULL);
}

uint64_t keProcOfPid(pid_t pid)
{
    if (!keIsInitialized()) return 0;
    uint64_t proc = 0;
    keTaskOfPidAllproc(pid, &proc);
    return proc;
}
