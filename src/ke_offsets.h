//
//  ke_offsets.h — accessor for the per-build offset table
//
#ifndef KE_OFFSETS_H
#define KE_OFFSETS_H

#include "offsets/offsets.h"

const KEBuildOffsets *keOffsetsForBuild(const char *build, const char *arch);
void keOffsetsApplyDefaults(KEBuildOffsets *o);

#endif
