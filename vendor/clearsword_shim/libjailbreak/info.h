//
//  shim/libjailbreak/info.h — minimal stand-in for Dopamine's offset
//  dictionary globals, sufficient for the vendored ClearSword core.
//  The real values are filled by keOffsetsFillClearswordShim() from the
//  per-build offsets table (offsets/ke_offsets_generated.h).
//
#ifndef LIBJAILBREAK_INFO_SHIM_H
#define LIBJAILBREAK_INFO_SHIM_H

#include <stdint.h>

typedef struct {
    uint64_t socket, icmp6filt, list_next, pcbinfo;
} ke_shim_inpcb_t;

typedef struct {
    uint64_t ipi_zone;
} ke_shim_inpcbinfo_t;

typedef struct {
    uint64_t kt_zv_zv_name;
} ke_shim_kalloc_type_view_t;

typedef struct {
    uint64_t usecount, proto;
} ke_shim_socket_t;

typedef struct {
    uint64_t input;
} ke_shim_protosw_t;

typedef struct {
    struct {
        ke_shim_inpcb_t inpcb;
        ke_shim_inpcbinfo_t inpcbinfo;
        ke_shim_kalloc_type_view_t kalloc_type_view;
        ke_shim_socket_t socket;
        ke_shim_protosw_t protosw;
    } kernelStruct;
    struct {
        uint64_t staticBase;
    } kernelConstant;
} KEShimSystemInfo;

extern KEShimSystemInfo gSystemInfo;

#define koffsetof(structname, member) (gSystemInfo.kernelStruct.structname.member)
#define kconstant(name)               (gSystemInfo.kernelConstant.name)
#define ksizeof(structname)           (0)

#endif
