//
//  ke_offsets.c — per-build offsets + fallback defaults
//
//  The table ships empty on purpose: offsets are build-specific and must be
//  generated from real kernelcaches (tools/gen_offsets, XPF-based) exactly
//  the way Dopamine builds its offset dictionary at jailbreak time.
//
//  Struct offsets that are stable across 15.x/16.x are prefilled below from
//  kfd's verified tables (Félix Poulin-Bélanger / opa334, MIT):
//    proc { list_next 0x0, list_prev 0x8, task 0x10, pid 0x68 (15.x) / 0x60 (16.x) }
//    task { map 0x28 }, vm_map { hdr 0x10 }, vm_map_header { last 0, first 8, ... }
//
//  Note: proc.pid / proc.fd layouts vary slightly between builds — a real
//  offsets-table entry or XPF always wins over the defaults.
//
#include "ke_internal.h"
#include "ke_offsets_generated.h"

static KEBuildOffsets gCurrentOffsets = { 0 };

const KEBuildOffsets *keOffsetsForBuild(const char *build, const char *arch)
{
    if (!build || !arch) return NULL;
    for (size_t i = 0; keOffsetsTable[i].build != NULL; i++) {
        if (strcmp(keOffsetsTable[i].build, build) == 0 && strcmp(keOffsetsTable[i].arch, arch) == 0) {
            gCurrentOffsets = keOffsetsTable[i];
            keOffsetsApplyDefaults(&gCurrentOffsets);
            return &gCurrentOffsets;
        }
    }
    return NULL;
}

const KEBuildOffsets *keOffsetsForCurrentBuild(void)
{
    const KEBuildOffsets *o = keOffsetsForBuild(keEnv.build, keEnv.arch);
    if (o) return o;

    // No table entry: still hand out defaults so that code paths guarded by
    // explicit null-checks (allproc etc.) can use the stable struct offsets.
    memset(&gCurrentOffsets, 0, sizeof(gCurrentOffsets));
    gCurrentOffsets.build = keEnv.build;
    gCurrentOffsets.arch = keEnv.arch;
    keOffsetsApplyDefaults(&gCurrentOffsets);
    return &gCurrentOffsets;
}

void keOffsetsApplyDefaults(KEBuildOffsets *o)
{
    if (o->procListNext == 0 && o->procListPrev == 0) {
        o->procListNext = 0x0;
        o->procListPrev = 0x8;
        o->procTask = 0x10;
    }
    if (keEnv.major >= 16) {
        o->procPid = o->procPid ? o->procPid : 0x60;
        // iOS 16+ (Dopamine libjailbreak info.c, darwin 22.x)
        o->procFd = o->procFd ? o->procFd : 0xD0;
        o->filedescOfilesStart = o->filedescOfilesStart ? o->filedescOfilesStart : 0x28;
    } else {
        o->procPid = o->procPid ? o->procPid : 0x68;
        // iOS 15.x: 15.0 uses 0xE0, 15.2+ moved to 0xD8
        o->procFd = o->procFd ? o->procFd : 0xD8;
        o->filedescOfilesStart = o->filedescOfilesStart ? o->filedescOfilesStart : 0x20;
    }
    o->taskMap = o->taskMap ? o->taskMap : 0x28;

    // vm_map / vm_map_header — composite offsets as consumed by the kfd
    // driver (Dopamine kfd.m mapping): hdr@0x10 in vm_map.
    if (o->vmMapHdrLast == 0 && o->vmMapHdrFirst == 0) {
        o->vmMapHdrLast = 0x10 + 0x0;
        o->vmMapHdrFirst = 0x10 + 0x8;
        o->vmMapMinOffset = 0x10 + 0x10;
        o->vmMapMaxOffset = 0x10 + 0x18;
    }
    if (o->procObjectSize == 0) {
        // Best-effort: only used as "proc + size == task" fallback when
        // proc_task is unavailable; the kfd path sets proc__task explicitly.
        o->procObjectSize = (keEnv.major >= 16) ? 0x730 : 0x4B0;
    }
}
