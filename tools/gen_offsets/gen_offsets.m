//
//  gen_offsets.m — offline generator (host macOS): kernelcache + XPF in,
//  KEBuildOffsets initializer out.
//
//  Build:
//    clang -fobjc-arc -framework Foundation gen_offsets.m \
//      -I../../vendor/XPF/src -I../../vendor/XPF/external/ChOma/include \
//      ../../vendor/XPF/src/*.c ../../vendor/XPF/external/ChOma/src/*.c \
//      $(ls ../../vendor/XPF/external/img4lib/*.c ../../vendor/XPF/external/img4lib/libDER/*.c ../../vendor/XPF/external/img4lib/libvfs/*.c | grep -v vfs_lzvn) \
//      -lcompression -o /tmp/gen_offsets
//
//  Run:
//    /tmp/gen_offsets <kernelcache> [sptm] [txm] "build" "arch"
//
//  The printed initializer goes into src/ke_offsets_generated.h.
//
#import <Foundation/Foundation.h>
#import "../../vendor/XPF/src/xpf.h"

int main(int argc, const char *argv[]) {
    if (argc < 5) {
        printf("usage: gen_offsets <kernelcache> [sptm] [txm] <build> <arch>\n");
        return 1;
    }
    const char *sptm = argc >= 6 ? argv[2] : NULL;
    const char *txm  = argc >= 7 ? argv[3] : NULL;

    if (xpf_start_with_kernel_path(argv[1], sptm, txm) != 0) {
        printf("XPF start failed: %s\n", xpf_get_error());
        return 1;
    }

    char *sets[] = { "translation", "struct", "physrw", "perfkrw", NULL, NULL };
    uint32_t idx = 0;
    while (sets[idx] != NULL) idx++;
    if (xpf_set_is_supported("perfkrw")) sets[idx++] = "perfkrw";

    xpc_object_t dict = xpf_construct_offset_dictionary((const char **)sets);
    if (!dict) {
        printf("XPF error: %s\n", xpf_get_error());
        return 1;
    }

    __block uint64_t allproc = 0, t1sz = 0, mask = 0;
    xpc_dictionary_apply(dict, ^bool(const char *key, xpc_object_t value) {
        uint64_t v = (xpc_get_type(value) == XPC_TYPE_UINT64) ? xpc_uint64_get_value(value) : 0;
        if (!strcmp(key, "kernelSymbol.allproc")) allproc = v;
        if (!strcmp(key, "kernelConstant.T1SZ_BOOT")) t1sz = v;
        if (!strcmp(key, "kernelConstant.ARM_TT_L1_INDEX_MASK")) mask = v;
        printf("// XPF: 0x%016llx <- %s\n", v, key);
        return true;
    });

    printf("\nstatic const KEBuildOffsets keOffsetsEntry_%s_%s = {\n", argv[4], argv[5]);
    printf("    .build = \"%s\", .arch = \"%s\",\n", argv[4], argv[5]);
    printf("    .allproc = 0x%016llxULL, .staticBase = 0x%016llxULL,\n", allproc, gXPF.kernelBase);
    printf("    .t1szBoot = 0x%016llxULL, .armTTL1IndexMask = 0x%016llxULL,\n", t1sz, mask);
    printf("    // TODO (per build, from KDK headers / IDA):\n");
    printf("    .procListNext = 0x0, .procListPrev = 0x8, .procTask = 0x10,\n");
    printf("    .procPid = /* 0x60 (16.x) / 0x68 (15.x) */ 0, .procFd = 0xf8, .filedescOfilesStart = 0x20,\n");
    printf("    .procObjectSize = 0, .taskMap = 0x28,\n");
    printf("    .vmMapHdrFirst = 0, .vmMapHdrLast = 0, .vmMapMinOffset = 0, .vmMapMaxOffset = 0, .vmMapPmap = 0,\n");
    printf("    .inpcbSocket = 0, .inpcbIcmp6filt = 0, .inpcbListNext = 0, .inpcbPcbinfo = 0,\n");
    printf("    .inpcbinfoIpiZone = 0, .kallocTypeViewKtZvZvName = 0,\n");
    printf("    .socketSoCount = 0, .socketSoProto = 0, .protoswPrInput = 0,\n");
    printf("};\n");

    xpf_stop();
    return 0;
}
