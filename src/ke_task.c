//
//  ke_task.c — task_for_pid wrapper with extmod sanitization
//
#include "ke_internal.h"

kern_return_t keTaskForPid(pid_t pid, mach_port_t *taskOut, KETaskForPidFlags flags)
{
    if (!taskOut) return KERN_INVALID_ARGUMENT;

    kern_return_t kr = task_for_pid(mach_task_self(), pid, taskOut);
    if (kr != KERN_SUCCESS) return kr;

    if (flags & KE_TFP_FLAG_ZERO_TARGET) {
        keZeroExtmodOfPid(pid);
    }
    if (flags & KE_TFP_FLAG_ZERO_CALLER) {
        keZeroExtmodSelf();
    }
    return KERN_SUCCESS;
}
