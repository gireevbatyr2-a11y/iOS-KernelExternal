//
//  ke_dispatch.c — version matrix & backend selection
//
//  Ranges/priorities mirror Dopamine 3.x exploit manifests
//  (Application/Dopamine/Exploits/*/Info.plist):
//    physpuppet      1000  15.0–15.7.3, 16.0–16.3.1
//    landa            900  15.0–15.8.6, 16.0–16.6.1
//    ClearSword       895  15.0–18.7.1 (requires per-build offsets)
//    smith            600  15.0–15.7.6, 16.0–16.5
//  multicast_bytecopy (15.0–15.1.1) and weightBufs (15.2–15.5 arm64e) are
//  intentionally not bundled; landa/physpuppet cover the same versions here.
//
#include "ke_internal.h"

typedef struct {
    uint8_t startMajor, startMinor, endMajor, endMinor;
    KEBackendID id;
    int priority;
} KEBackendRange;

// HARD RULE: never fall back from darksword to landa on 16.6+ — a failed
// landa run (sem_open MISS) corrupts kernel state and later panics the device
// (shared_region_pager_data_return). kfd only ever runs on its supported range.
static const KEBackendRange keBackendRanges[] = {
    { 16, 6, 17, 3,  KE_BACKEND_DARKSWORD,      1200 },
    { 16, 0, 16, 5,  KE_BACKEND_KFD_LANDA,      1000 },
    { 15, 0, 15, 8,  KE_BACKEND_KFD_LANDA,      1000 },
    { 16, 0, 16, 3,  KE_BACKEND_KFD_PHYSPUPPET,  900 },
    { 15, 0, 15, 7,  KE_BACKEND_KFD_PHYSPUPPET, 1000 },
    { 15, 0, 15, 7,  KE_BACKEND_CLEARSWORD,      895 },
    { 16, 0, 16, 5,  KE_BACKEND_KFD_SMITH,       800 },
    { 15, 0, 15, 7,  KE_BACKEND_KFD_SMITH,       900 },
};

static bool keRangeCovers(const KEBackendRange *r)
{
    uint32_t v = (uint32_t)keEnv.major * 100 + keEnv.minor;
    uint32_t s = (uint32_t)r->startMajor * 100 + r->startMinor;
    uint32_t e = (uint32_t)r->endMajor * 100 + r->endMinor;
    return (v >= s && v <= e);
}

const KEBackendOps *keBackendForID(KEBackendID id)
{
    switch (id) {
        case KE_BACKEND_KFD_PHYSPUPPET: return &keBackendKfdPhyspuppet;
        case KE_BACKEND_KFD_LANDA:      return &keBackendKfdLanda;
        case KE_BACKEND_KFD_SMITH:      return &keBackendKfdSmith;
        case KE_BACKEND_CLEARSWORD:     return &keBackendClearsword;
        case KE_BACKEND_DARKSWORD:      return &keBackendDarksword;
        default: return NULL;
    }
}

static bool keBackendPrerequisitesMet(KEBackendID id)
{
    if (id == KE_BACKEND_DARKSWORD) {
        if (keEnv.major < 16) return false;
        if (!strstr(keEnv.arch, "64e")) return false; // lara DarkSword is arm64e-only
    } else if (id == KE_BACKEND_CLEARSWORD) {
        const KEBuildOffsets *o = keOffsetsForCurrentBuild();
        if (!o || !o->inpcbSocket || !o->inpcbListNext || !o->inpcbPcbinfo
            || !o->inpcbinfoIpiZone || !o->kallocTypeViewKtZvZvName
            || !o->socketSoProto || !o->protoswPrInput) {
            return false;
        }
    }
    // kfd backends: 15.0–16.5.x, any arch (15/16e). Runtime proc-layout
    // derivation (Serotonin-style) needs no offsets table.
    return true;
}

int keDispatchCandidates(KEBackendID preferred, KEBackendID *out, int maxOut)
{
    int n = 0;
    if (preferred != KE_BACKEND_AUTO) {
        if (n < maxOut) out[n++] = preferred;
        return n;
    }
    // highest priority first; skip candidates whose prerequisites are missing
    KEBackendID ids[5] = { KE_BACKEND_DARKSWORD, KE_BACKEND_KFD_PHYSPUPPET,
                           KE_BACKEND_KFD_LANDA, KE_BACKEND_CLEARSWORD,
                           KE_BACKEND_KFD_SMITH };
    int prio[5] = { 0 };
    for (size_t i = 0; i < sizeof(keBackendRanges) / sizeof(keBackendRanges[0]); i++) {
        const KEBackendRange *r = &keBackendRanges[i];
        if (!keRangeCovers(r)) continue;
        for (int k = 0; k < 5; k++) {
            if (ids[k] == r->id && r->priority > prio[k]) prio[k] = r->priority;
        }
    }
    for (int picked = 0; picked < 5; picked++) {
        int best = -1, bestPrio = -1;
        for (int k = 0; k < 5; k++) {
            if (prio[k] > 0 && prio[k] > bestPrio) { bestPrio = prio[k]; best = k; }
        }
        if (best < 0) break;
        prio[best] = -1;
        if (keBackendPrerequisitesMet(ids[best]) && n < maxOut) {
            out[n++] = ids[best];
        }
    }
    return n;
}
