//
//  KernelExternal.h — userland kernel external for iOS 15.0 – 17.3.1
//
//  Architecture follows opa334/Dopamine 3.x: exploit backends provide kernel
//  r/w, everything else (task port acquisition, extmod counter hygiene) runs
//  in userland on top of stock APIs.
//
//  Copyright (c) 2026 reverseengeenir. MIT licensed (see LICENSE).
//

#ifndef KERNEL_EXTERNAL_H
#define KERNEL_EXTERNAL_H

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define KE_VERSION "0.1.0"

typedef enum {
    KE_OK                        =  0,
    KE_ERR_UNSUPPORTED_VERSION   = -1,
    KE_ERR_UNSUPPORTED_DEVICE    = -2,
    KE_ERR_EXPLOIT_FAILED        = -3,
    KE_ERR_OFFSETS_MISSING       = -4,
    KE_ERR_NOT_INITIALIZED       = -5,
    KE_ERR_NO_KERNEL_MEMORY      = -6,
    KE_ERR_TFP_FAILED            = -7,
    KE_ERR_CALIBRATION_FAILED    = -8,
    KE_ERR_INVALID_ARGUMENT      = -9,
    KE_ERR_BACKEND_UNSUPPORTED   = -10,
    KE_ERR_EXPLOIT_ALREADY_USED  = -11,
    KE_ERR_PROC_NOT_FOUND        = -12,
    KE_ERR_KRW                   = -13,
} KEError;

typedef enum {
    KE_BACKEND_AUTO = 0,
    KE_BACKEND_KFD_PHYSPUPPET,
    KE_BACKEND_KFD_LANDA,
    KE_BACKEND_KFD_SMITH,
    KE_BACKEND_CLEARSWORD,
    KE_BACKEND_DARKSWORD,
} KEBackendID;

typedef struct KEConfig {
    KEBackendID preferredBackend;
    const char *kernelcachePath; // required only by the ClearSword backend
    uint32_t puafPages;          // kfd: number of dangling PTE pages, 0 = auto
    bool verbose;
} KEConfig;

typedef struct KEExtmodCounters {
    int64_t taskForPidCount;
    int64_t taskForPidCallerCount;
    int64_t threadCreationCount;
    int64_t threadCreationCallerCount;
    int64_t threadSetStateCount;
    int64_t threadSetStateCallerCount;
} KEExtmodCounters;

typedef enum {
    KE_TFP_FLAG_NONE        = 0,
    KE_TFP_FLAG_ZERO_TARGET = 1 << 0,
    KE_TFP_FLAG_ZERO_CALLER = 1 << 1,
    KE_TFP_FLAG_ZERO_BOTH   = (KE_TFP_FLAG_ZERO_TARGET | KE_TFP_FLAG_ZERO_CALLER),
} KETaskForPidFlags;

// Other-process user memory access (Dopamine physrw-style, no jailbreak needed):
// proc -> task -> vm_map -> pmap -> ttep, manual page-table walk, physmap alias.
int keUserRead(pid_t pid, uint64_t uaddr, void *buf, size_t size);
int keUserWrite(pid_t pid, uint64_t uaddr, const void *buf, size_t size);
uint64_t keKernelBase(void);

// Lifecycle
int keInit(const KEConfig *config);
void keDeinit(void);
bool keIsInitialized(void);
const char *keActiveBackendName(void);

// Kernel read/write (page-aware, chunked)
int keKreadBuf(uint64_t kaddr, void *out, size_t size);
int keKwriteBuf(uint64_t kaddr, const void *in, size_t size);
int keKread64(uint64_t kaddr, uint64_t *out);
int keKwrite64(uint64_t kaddr, uint64_t value);

// Process / task resolution (kernel addresses)
uint64_t keTaskOfPid(pid_t pid);
uint64_t keProcOfPid(pid_t pid);

// extmod (vm_extmod_statistics) hygiene
int keGetExtmodOfPid(pid_t pid, KEExtmodCounters *out);
int keGetExtmodNative(pid_t pid, KEExtmodCounters *out); // no kernel r/w needed, entitlement required
int keZeroExtmodOfPid(pid_t pid);
int keZeroExtmodSelf(void);

// External attachment (task port + mach_vm_* — the "external" layer)
typedef struct KEProcessInfo {
    pid_t pid;
    uid_t uid;
    char name[33];
} KEProcessInfo;

int keProcessList(KEProcessInfo **out, size_t *count); // caller frees *out
kern_return_t keAttach(pid_t pid, KETaskForPidFlags flags);
void keDetach(void);
mach_port_t keAttachedTask(void);
pid_t keAttachedPid(void);
kern_return_t keReadMem(uint64_t addr, void *dst, size_t size);
kern_return_t keWriteMem(uint64_t addr, const void *src, size_t size);
kern_return_t keProtectMem(uint64_t addr, size_t size, vm_prot_t prot);
kern_return_t keRegionInfo(uint64_t addr, uint64_t *startOut, size_t *sizeOut, vm_prot_t *protOut);

// task_for_pid wrapper: stock API + kernel-side extmod counter zeroing
kern_return_t keTaskForPid(pid_t pid, mach_port_t *taskOut, KETaskForPidFlags flags);

// Read extmod counters straight from a task port (TASK_EXTMOD_INFO, flavor 19)
kern_return_t keGetExtmodFromPort(mach_port_t taskPort, KEExtmodCounters *out);

const char *keErrorString(int error);
const char *keBackendName(KEBackendID id);

#endif // KERNEL_EXTERNAL_H
