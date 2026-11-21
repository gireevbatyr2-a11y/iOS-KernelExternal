//
//  ke_offsets_generated.h — per-build offset table (empty by default)
//
//  Generate entries with tools/gen_offsets/gen_offsets.sh on a host Mac with
//  the matching kernelcache (KDK or ipsw extraction), or fill them manually.
//
#ifndef KE_OFFSETS_GENERATED_H
#define KE_OFFSETS_GENERATED_H

#include "offsets/offsets.h"

// Example entry (values illustrative — do not trust without verification):
//
// static const KEBuildOffsets _off_20H18_arm64 = {
//     .build = "20H18", .arch = "arm64",
//     .allproc = 0x..., .staticBase = 0xfffffff007000000,
//     .t1szBoot = 0x10, .armTTL1IndexMask = 0x0000fffff0000000ULL,
//     .procListNext = 0x0, .procListPrev = 0x8, .procTask = 0x10,
//     .procPid = 0x60, .procFd = 0xf8, .filedescOfilesStart = 0x0,
//     .procObjectSize = 0x538, .taskMap = 0x28,
//     .vmMapHdrFirst = 0x30, .vmMapHdrLast = 0x28,
//     .vmMapMinOffset = 0x38, .vmMapMaxOffset = 0x40, .vmMapPmap = 0x88,
//     ...
// };

static const KEBuildOffsets keOffsetsTable[] = {
    { .build = NULL }, // terminator — fill via tools/gen_offsets
};

#endif
