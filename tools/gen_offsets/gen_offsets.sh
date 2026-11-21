#!/bin/bash
#
# gen_offsets.sh — generate the per-build offsets table entry for
# src/ke_offsets_generated.h using XPF (opa334, MIT) on a host Mac.
#
# Usage:
#   ./tools/gen_offsets/gen_offsets.sh <kernelcache> [<sptm>] [<txm>] <build> <arch>
#
# The kernelcache must match the target build (extract from an IPSW with
# `ipsw kernel dec` or pull from a Kernel Debug Kit).
#
# What XPF resolves (sets: base, translation, struct, physrw, perfkrw):
#   kernelSymbol.allproc              -> allproc
#   kernelConstant.staticBase         <- gXPF.kernelBase (same as Dopamine's DOJailbreaker)
#   kernelConstant.T1SZ_BOOT          -> t1szBoot
#   kernelConstant.ARM_TT_L1_INDEX_MASK -> armTTL1IndexMask
#   kernelSymbol.gPhysBase/gPhysSize/gVirtBase/ptov_table -> kernelG*
#   kernelSymbol.cdevsw / vn_kqfilter / perfmon_* (perfkrw set) -> kernelC*
#
# The remaining struct offsets (inpcb/socket/protosw for ClearSword, proc
# object_size, etc.) are documented in offsets/README.md.
#
set -euo pipefail

KERNEL="$1"; shift
BUILD="${1:?build}"; shift
ARCH="${1:?arch}"; shift
SPTM="${1:-}"; TXM="${2:-}"

XPF_BIN="${XPF_BIN:-xpf_test}"   # built from opa334/XPF (make output/macos/xpf_test)

echo "Running XPF on $KERNEL ($BUILD $ARCH)..."
if [ -n "$SPTM" ]; then
    "$XPF_BIN" "$KERNEL" "$SPTM" "$TXM" | tee /tmp/xpf_out.txt
else
    "$XPF_BIN" "$KERNEL" | tee /tmp/xpf_out.txt
fi

get() { awk -v k="$1" '$2 == k { print $1; exit }' /tmp/xpf_out.txt; }

cat <<EOF

// --- paste into src/ke_offsets_generated.h ---
static const KEBuildOffsets _off_${BUILD}_${ARCH} = {
    .build = "${BUILD}", .arch = "${ARCH}",
    .allproc           = $(get kernelSymbol.allproc),
    .staticBase        = $(get kernelConstant.staticBase),
    .t1szBoot          = $(get kernelConstant.T1SZ_BOOT),
    .armTTL1IndexMask  = $(get kernelConstant.ARM_TT_L1_INDEX_MASK),
    .kernelGVirtBase   = $(get kernelSymbol.gVirtBase),
    .kernelGPhysBase   = $(get kernelSymbol.gPhysBase),
    .kernelGPhysSize   = $(get kernelSymbol.gPhysSize),
    .kernelPtovTable   = $(get kernelSymbol.ptov_table),
    .kernelCdevsw      = $(get kernelSymbol.cdevsw),
    .kernelVnKqfilter  = $(get kernelSymbol.vn_kqfilter),
    .kernelPerfmonDevOpen = $(get kernelSymbol.perfmon_dev_open),
    .kernelPerfmonDevices = $(get kernelSymbol.perfmon_devices),
    // struct offsets (KDK/IDA — see offsets/README.md):
    .procObjectSize = 0xTODO,
    .inpcbSocket = 0xTODO, .inpcbIcmp6filt = 0xTODO,
    .inpcbListNext = 0xTODO, .inpcbPcbinfo = 0xTODO,
    .inpcbinfoIpiZone = 0xTODO, .kallocTypeViewKtZvZvName = 0xTODO,
    .socketSoCount = 0xTODO, .socketSoProto = 0xTODO, .protoswPrInput = 0xTODO,
};
EOF
