// xpf_compat.h — compatibility shim for lara-style offsets.m usage against
// upstream XPF: older single-arg start API + t1sz_boot helper.
#ifndef xpf_compat_h
#define xpf_compat_h

#include "xpf.h"

static inline int xpf_start_with_kernel_path_compat(const char *kernelPath) {
    return xpf_start_with_kernel_path(kernelPath, NULL, NULL);
}
#define xpf_start_with_kernel_path(a) xpf_start_with_kernel_path_compat(a)

static inline uint64_t xpf_gett1szboot(void) {
    uint64_t pointer_mask = xpf_item_resolve("kernelConstant.pointer_mask");
    uint64_t T1SZ_BOOT = 0;
    for (uint64_t i = 64; i > 0; i--) {
        if (pointer_mask & (1ULL << (i - 1))) {
            T1SZ_BOOT++;
        }
    }
    return T1SZ_BOOT;
}

#endif
