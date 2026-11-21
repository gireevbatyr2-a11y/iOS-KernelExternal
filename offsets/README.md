# Offsets

`offsets.h` describes the per-build offset table. `src/ke_offsets_generated.h`
ships **empty** on purpose — every value here must come from a real kernelcache
of the matching build, never from guesses.

Generation paths:

1. **tools/gen_offsets/gen_offsets.sh** (host macOS, XPF from opa334/XPF):
   resolves `kernelSymbol.allproc`, `kernelConstant.T1SZ_BOOT`,
   `kernelConstant.ARM_TT_L1_INDEX_MASK`, `kernelConstant.staticBase`
   (== `gXPF.kernelBase`), plus translation/perfkrw symbols.
2. **KDK / IDA / Ghidra**: the remaining entries are plain XNU struct offsets
   (`inpcb`, `socket`, `protosw`, `kalloc_type_view`, `inpcbinfo`) — take them
   from the KDK headers of the matching SDK build and put them into the table.
3. `vm_extmod_statistics` offset inside `struct task` is **not** part of the
   table: the library self-calibrates it at runtime (see src/ke_extmod.c).

Entries are keyed by `(kern.osversion, kernel arch)`. arch is `arm64` or
`arm64e` (A12+ SoCs run arm64e kernels).
