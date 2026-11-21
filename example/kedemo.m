//
//  kedemo.m — demonstrate the kernel external:
//    1. task_for_pid() on a target process (stock API)
//    2. kernel-side zeroing of vm_extmod_statistics (target + caller)
//    3. verification via TASK_EXTMOD_INFO (native, no kernel)
//
#import <Foundation/Foundation.h>
#import <KernelExternal.h>
#import <stdio.h>
#import <stdlib.h>

static void printCounters(const char *label, pid_t pid, const KEExtmodCounters *c)
{
    printf("[%s] pid %d extmod:\n", label, pid);
    printf("  task_for_pid        (target): %lld\n", c->taskForPidCount);
    printf("  task_for_pid        (caller): %lld\n", c->taskForPidCallerCount);
    printf("  thread_creation     (target): %lld\n", c->threadCreationCount);
    printf("  thread_creation     (caller): %lld\n", c->threadCreationCallerCount);
    printf("  thread_set_state    (target): %lld\n", c->threadSetStateCount);
    printf("  thread_set_state    (caller): %lld\n", c->threadSetStateCallerCount);
}

int main(int argc, char **argv, char **envp)
{
    @autoreleasepool {
        if (argc < 2) {
            fprintf(stderr, "usage: kedemo <pid>\n");
            return 1;
        }
        pid_t pid = (pid_t)atoi(argv[1]);

        KEConfig cfg = { .verbose = true };
        int r = keInit(&cfg);
        if (r != KE_OK) {
            printf("keInit failed: %s (backend=%s)\n", keErrorString(r), keActiveBackendName() ?: "none");
            return 1;
        }
        printf("kernel external active: backend=%s\n", keActiveBackendName());

        KEExtmodCounters before = { 0 }, after = { 0 };
        if (keGetExtmodOfPid(pid, &before) == KE_OK) {
            printCounters("before", pid, &before);
        } else {
            printf("warning: could not read extmod counters before tfp\n");
        }

        mach_port_t task = MACH_PORT_NULL;
        kern_return_t kr = keTaskForPid(pid, &task, KE_TFP_FLAG_ZERO_BOTH);
        if (kr != KERN_SUCCESS) {
            printf("keTaskForPid failed: kr=%d (check entitlements: com.apple.system-task-ports)\n", kr);
            keDeinit();
            return 1;
        }
        printf("task_for_pid OK, task port: 0x%x\n", task);

        if (keGetExtmodOfPid(pid, &after) == KE_OK) {
            printCounters("after (kernel zeroed)", pid, &after);
        }

        KEExtmodCounters native = { 0 };
        if (keGetExtmodFromPort(task, &native) == KERN_SUCCESS) {
            printCounters("native TASK_EXTMOD_INFO", pid, &native);
        } else {
            printf("TASK_EXTMOD_INFO unavailable (missing entitlement or unsupported flavor)\n");
        }

        mach_port_deallocate(mach_task_self(), task);
        keDeinit();
    }
    return 0;
}
