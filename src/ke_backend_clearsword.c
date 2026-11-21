//
//  ke_backend_clearsword.c — krw backend over ClearSword (opa334, MIT),
//  vendored unmodified under vendor/clearsword_core. The vendored code talks
//  to the offset provider through the libjailbreak shim (koffsetof/kconstant),
//  which is filled from the per-build offsets table by ke_offsets.c.
//
//  ClearSword resolves the kernel slide at runtime by walking socket/protosw
//  structures — no kernelcache is needed at runtime; the offsets table must
//  be generated offline from the matching kernelcache (tools/gen_offsets).
//
#include "ke_internal.h"

#ifdef KE_ENABLE_CLEARSWORD

#include "common.h"
#include "poc.h"
#include "krw.h"#include "utils.h"

static bool keCswOffsetsPresent(const KEBuildOffsets *o)
{
    return o->inpcbSocket && o->inpcbIcmp6filt && o->inpcbListNext && o->inpcbPcbinfo
        && o->inpcbinfoIpiZone && o->kallocTypeViewKtZvZvName
        && o->socketSoCount && o->socketSoProto && o->protoswPrInput
        && o->staticBase;
}

static int keCswInit(const KEConfig *config)
{
    const KEBuildOffsets *o = keOffsetsForCurrentBuild();
    if (!o) return KE_ERR_OFFSETS_MISSING;
    if (!keCswOffsetsPresent(o)) return KE_ERR_OFFSETS_MISSING;

    g_offsets.ios_major_version = (uint32_t)keEnv.major;
    g_offsets.ios_minor_version = (uint32_t)keEnv.minor;

    // utils.c offsets_init() copies the shim values into g_offsets
    if (offsets_init() != 0) {
        return KE_ERR_OFFSETS_MISSING;
    }
    if (clearsword_run() != 0) {
        return KE_ERR_EXPLOIT_FAILED;
    }
    return KE_OK;
}

static int keCswReadBuf(uint64_t kaddr, void *out, size_t size)
{
    return clearsword_kreadbuf(kaddr, out, size);
}

static int keCswWriteBuf(uint64_t kaddr, const void *in, size_t size)
{
    return clearsword_kwritebuf(kaddr, in, size);
}

const KEBackendOps keBackendClearsword = {
    .name = "clearsword", .id = KE_BACKEND_CLEARSWORD,
    .init = keCswInit, .deinit = NULL,
    .kreadbuf = keCswReadBuf, .kwritebuf = keCswWriteBuf, .vtophys = NULL,
};

#else

const KEBackendOps keBackendClearsword = {
    .name = "clearsword", .id = KE_BACKEND_CLEARSWORD,
    .init = NULL, .deinit = NULL,
    .kreadbuf = NULL, .kwritebuf = NULL, .vtophys = NULL,
};

#endif
