//
//  ke_attach.c — external process attachment layer
//
//  The "external" model: the tool is NOT injected into the target. It
//  acquires the target task port via task_for_pid and operates on the
//  process memory through the public mach_vm_* interface. The kernel
//  backend is used for one purpose only: zeroing the extmod counters
//  that task_for_pid creates on iOS 16+.
//
#include "ke_internal.h"

#include <sys/sysctl.h>
#include <sys/utsname.h>

static mach_port_t gAttachedTask = MACH_PORT_NULL;
static pid_t gAttachedPid = -1;

static kern_return_t memChunkOp(uint64_t addr, void *buf, size_t size, bool write)
{
    kern_return_t kr;
    if (write) {
        kr = mach_vm_write(gAttachedTask, addr, (vm_offset_t)buf, (mach_msg_type_number_t)size);
    } else {
        mach_vm_size_t localSize = 0;
        kr = mach_vm_read_overwrite(gAttachedTask, addr, size, (mach_vm_address_t)(uintptr_t)buf, &localSize);
    }
    return kr;
}

kern_return_t keAttach(pid_t pid, KETaskForPidFlags flags)
{
    if (pid <= 0) return KERN_INVALID_ARGUMENT;
    if (!keIsInitialized() && (flags & (KE_TFP_FLAG_ZERO_TARGET | KE_TFP_FLAG_ZERO_CALLER))) {
        return KERN_FAILURE;
    }

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = keTaskForPid(pid, &task, flags);
    if (kr != KERN_SUCCESS) return kr;

    keDetach();
    gAttachedTask = task;
    gAttachedPid = pid;
    return KERN_SUCCESS;
}

void keDetach(void)
{
    if (gAttachedTask != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), gAttachedTask);
        gAttachedTask = MACH_PORT_NULL;
        gAttachedPid = -1;
    }
}

mach_port_t keAttachedTask(void)
{
    return gAttachedTask;
}

pid_t keAttachedPid(void)
{
    return gAttachedPid;
}

kern_return_t keReadMem(uint64_t addr, void *dst, size_t size)
{
    if (gAttachedTask == MACH_PORT_NULL || size == 0 || dst == NULL) {
        return KERN_INVALID_ARGUMENT;
    }

    uint8_t *out = (uint8_t *)dst;
    size_t done = 0;
    while (done < size) {
        size_t chunk = size - done > 4096 ? 4096 : size - done;
        kern_return_t kr = memChunkOp(addr + done, out + done, chunk, false);
        if (kr != KERN_SUCCESS) return kr;
        done += chunk;
    }
    return KERN_SUCCESS;
}

kern_return_t keWriteMem(uint64_t addr, const void *src, size_t size)
{
    if (gAttachedTask == MACH_PORT_NULL || size == 0 || src == NULL) {
        return KERN_INVALID_ARGUMENT;
    }

    const uint8_t *in = (const uint8_t *)src;
    size_t done = 0;
    while (done < size) {
        size_t chunk = size - done > 2048 ? 2048 : size - done;
        kern_return_t kr = memChunkOp(addr + done, (void *)(in + done), chunk, true);
        if (kr == KERN_PROTECTION_FAILURE) {
            kr = keProtectMem(addr + done, chunk, VM_PROT_READ | VM_PROT_WRITE);
            if (kr == KERN_SUCCESS) {
                kr = memChunkOp(addr + done, (void *)(in + done), chunk, true);
            }
        }
        if (kr != KERN_SUCCESS) return kr;
        done += chunk;
    }
    return KERN_SUCCESS;
}

kern_return_t keProtectMem(uint64_t addr, size_t size, vm_prot_t prot)
{
    if (gAttachedTask == MACH_PORT_NULL || size == 0) {
        return KERN_INVALID_ARGUMENT;
    }
    return mach_vm_protect(gAttachedTask, addr, size, false, prot);
}

kern_return_t keRegionInfo(uint64_t addr, uint64_t *startOut, size_t *sizeOut, vm_prot_t *protOut)
{
    if (gAttachedTask == MACH_PORT_NULL) {
        return KERN_INVALID_ARGUMENT;
    }

    mach_vm_address_t region = (mach_vm_address_t)addr;
    mach_vm_size_t regionSize = 0;
    struct vm_region_basic_info_64 info = { 0 };
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t objectName = MACH_PORT_NULL;

    kern_return_t kr = mach_vm_region(gAttachedTask, &region, &regionSize,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &objectName);
    if (kr != KERN_SUCCESS) return kr;

    if (startOut) *startOut = (uint64_t)region;
    if (sizeOut) *sizeOut = (size_t)regionSize;
    if (protOut) *protOut = info.protection;
    if (objectName != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), objectName);
    return KERN_SUCCESS;
}

int keProcessList(KEProcessInfo **out, size_t *count)
{
    if (out == NULL || count == NULL) return KE_ERR_INVALID_ARGUMENT;
    *out = NULL;
    *count = 0;

    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t size = 0;
    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0) return KE_ERR_CALIBRATION_FAILED;

    struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
    if (procs == NULL) return KE_ERR_CALIBRATION_FAILED;
    if (sysctl(mib, 3, procs, &size, NULL, 0) != 0) {
        free(procs);
        return KE_ERR_CALIBRATION_FAILED;
    }

    size_t n = size / sizeof(struct kinfo_proc);
    KEProcessInfo *list = (KEProcessInfo *)calloc(n ? n : 1, sizeof(KEProcessInfo));
    if (list == NULL) {
        free(procs);
        return KE_ERR_CALIBRATION_FAILED;
    }

    size_t kept = 0;
    for (size_t i = 0; i < n; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 0) continue;
        const char *name = procs[i].kp_proc.p_comm;
        list[kept].pid = pid;
        list[kept].uid = procs[i].kp_eproc.e_ucred.cr_uid;
        strncpy(list[kept].name, name, sizeof(list[kept].name) - 1);
        kept++;
    }

    free(procs);
    *out = list;
    *count = kept;
    return KE_OK;
}
