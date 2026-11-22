include $(THEOS)/makefiles/common.mk

TARGET := iphone:latest:15.0
ARCHS := arm64 arm64e
THEOS_PACKAGE_SCHEME ?= rootless

LIBRARY_NAME = kernelexternal
kernelexternal_LINKAGE_TYPE = static

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
	vendor/darksword/persistence_stub.m

kernelexternal_CFLAGS = -Iinclude -Isrc -Ivendor/kpf -Ivendor -Ivendor/clearsword_shim -Ioffsets -Ivendor/darksword -Ivendor/darksword/pe -O2 -Wno-ambiguous-macro -Wno-gnu-folding-constant -Wno-unused-variable -Wno-unguarded-availability-new -Wno-unused-but-set-variable -Wno-unused-function

include $(THEOS_MAKE_PATH)/library.mk
