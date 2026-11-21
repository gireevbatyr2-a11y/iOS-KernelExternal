TARGET := iphone:latest:15.0
ARCHS := arm64 arm64e
THEOS_PACKAGE_SCHEME ?= rootless

TOOLS = kedemo

kedemo_FILES = kedemo.m
kedemo_CFLAGS = -I../include -I../offsets
kedemo_LIBS = kernelexternal
kedemo_LDFLAGS = -L../.theos/obj
kedemo_CODESIGN_FLAGS = --entitlements kedemo.entitlements

include $(THEOS_MAKE_PATH)/tool.mk
