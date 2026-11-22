//
//  ke_backend_darksword.c — krw backend over lara's DarkSword exploit
//
//  DarkSword (github.com/forestg10/lara-16.6.x-support, vendored under
//  vendor/darksword/) gives arbitrary kernel read/write through an
//  ICMPv6 socket OOB primitive:
//    - no PUAF: no corrupted physical pages, no memory hog, no Jetsam
//      pressure on the system (this is why lara runs stable overnight
//      while our kfd/landa build panicked after ~5 minutes of idle);
//    - repeatable per boot: re-running the exploit in a fresh process
//      works, so the app can crash/relaunch without a reboot;
//    - kread via getsockopt, kwrite via setsockopt on the corrupted
//      socket — kernel state only touched on demand.
//
//  Supported: iOS 16.0–17.3.x (offsets_init covers 16.x/17.x; we enable
//  the backend for the Dopamine-supported window 16.0–17.3.1). arm64e
//  handled via xpaci/PAC masks in the vendored code.
//
#include "ke_internal.h"
#include "darksword.h"
#include "offsets.h"
#include <mach/mach.h>

int keDarkswordInit(const KEConfig *config)
{
    (void)config;

    // Sanity: the vendored offsets must be initialized for this OS.
    offsets_init();
    if (!off_inpcb_inp_socket || !off_socket_so_proto || !off_protosw_pr_input) {
        KE_LOG("darksword: offsets not initialized (os=%s device=%s)", keEnv.osVersion, keEnv.machine);
        return KE_ERR_OFFSETS_MISSING;
    }

    KE_LOG("darksword: starting exploit (os=%s build=%s machine=%s)", keEnv.osVersion, keEnv.build, keEnv.machine);
    int rc = ds_run();
    if (rc != 0 || !ds_is_ready()) {
        KE_LOG("darksword: exploit failed rc=%d ready=%d", rc, ds_is_ready());
        return KE_ERR_EXPLOIT_FAILED;
    }

    uint64_t kbase = ds_get_kernel_base();
    KE_LOG("darksword: kernel r/w ready, kernel_base=0x%llx", kbase);

    gKeKrwIsPerf = false;
    return KE_OK;
}

static void keDarkswordDeinit(void)
{
    // The corrupted socket primitives live in this process only; no kernel
    // state needs to be (or can safely be) torn down. kfd's kclose-style
    // teardown is explicitly NOT needed here.
    KE_LOG("darksword: deinit (primitives intentionally left resident)");
}

static int keDarkswordReadBuf(uint64_t kaddr, void *out, size_t size)
{
    if (!ds_is_ready()) return -1;
    if (!out || size == 0) return 0;
    ds_kreadbuf(kaddr, out, size);
    return 0;
}

static int keDarkswordWriteBuf(uint64_t kaddr, const void *in, size_t size)
{
    if (!ds_is_ready()) return -1;
    if (!in || size == 0) return 0;
    ds_kwritebuf(kaddr, in, size);
    return 0;
}

const KEBackendOps keBackendDarksword = {
    .name      = "darksword",
    .id        = KE_BACKEND_DARKSWORD,
    .init      = keDarkswordInit,
    .deinit    = keDarkswordDeinit,
    .kreadbuf  = keDarkswordReadBuf,
    .kwritebuf = keDarkswordWriteBuf,
    .vtophys   = NULL,
};
