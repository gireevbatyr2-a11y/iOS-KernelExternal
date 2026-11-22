include $(THEOS)/makefiles/common.mk

TARGET := iphone:latest:15.0
ARCHS := arm64 arm64e
THEOS_PACKAGE_SCHEME ?= rootless

LIBRARY_NAME = kernelexternal
kernelexternal_LINKAGE_TYPE = static

CHOMA_INC := -Ivendor/xpf/external/ChOma/include -Ivendor/xpf/external/ChOma/include/choma
IMG4LIB_CFLAGS = -DUSE_COMMONCRYPTO -DUSE_LIBCOMPRESSION -DiOS10 -DDER_MULTIBYTE_TAGS=1 -D__unused='__attribute__((unused))' -Wno-variadic-macros -Wno-multichar -Wno-four-char-constants -Wno-unused-parameter

kernelexternal_FILES = \
	src/ke.c \
	src/ke_env.c \
	src/ke_dispatch.c \
	src/ke_krw.c \
	src/ke_offsets.c \
	src/ke_csw_shim.c \
	src/ke_proc.c \
	src/ke_extmod.c \
	src/ke_task.c \
	src/ke_attach.c \
	src/ke_backend_kfd.m \
	src/ke_backend_clearsword.c \
	src/ke_backend_darksword.m \
	vendor/clearsword_core/poc.c \
	vendor/kpf/patchfinder64.m \
	vendor/clearsword_core/krw.c \
	vendor/clearsword_core/phys_oob.c \
	vendor/clearsword_core/free_thread.c \
	vendor/clearsword_core/socket.c \
	vendor/clearsword_core/surface.c \
	vendor/clearsword_core/utils.c \
	vendor/darksword/darksword.m \
	vendor/darksword/offsets.m \
	vendor/darksword/utils.m \
	vendor/darksword/persistence_stub.m \
	vendor/darksword/vnode_stub.m \
	vendor/grabkernel/grabkernel.m \
	vendor/grabkernel/appledb.m \
	vendor/grabkernel/lgk_utils.m \
	vendor/partial/partial.m \
	vendor/xpf/xpf.c \
	vendor/xpf/common.c \
	vendor/xpf/non_ppl.c \
	vendor/xpf/ppl.c \
	vendor/xpf/sptm_txm.c \
	vendor/xpf/bad_recovery.c \
	vendor/xpf/decompress.c \
	$(wildcard vendor/xpf/external/ChOma/src/*.c) \
	$(filter-out vendor/xpf/external/img4lib/libvfs/vfs_lzvn.c,$(wildcard vendor/xpf/external/img4lib/lzss.c vendor/xpf/external/img4lib/libvfs/*.c vendor/xpf/external/img4lib/libDER/*.c))

kernelexternal_CFLAGS = $(IMG4LIB_CFLAGS) $(CHOMA_INC) \
	-Ivendor/xpf \
	-Ivendor/xpf/external/img4lib \
	-Ivendor/grabkernel \
	-Ivendor/partial/include \
	-Iinclude -Isrc -Ivendor/kpf -Ivendor -Ivendor/clearsword_shim \
	-Ioffsets -Ivendor/darksword -Ivendor/darksword/pe \
	-O2 -Wno-ambiguous-macro -Wno-gnu-folding-constant \
	-Wno-unused-variable -Wno-unguarded-availability-new \
	-Wno-unused-but-set-variable -Wno-unused-function -Wno-objc-missing-super-calls \
	-Wno-constant-conversion \
	-Wno-unused-parameter -Wno-deprecated-declarations

kernelexternal_LIBS = -lcompression -framework Security

include $(THEOS_MAKE_PATH)/library.mk
