include $(THEOS)/makefiles/common.mk

TARGET := iphone:latest:15.0
ARCHS := arm64 arm64e
THEOS_PACKAGE_SCHEME ?= rootless

APPLICATION_NAME = External

External_FILES = src/ExternalApp.m src/Engine.m src/RootViewController.m
External_FRAMEWORKS = UIKit IOSurface IOKit
External_CODESIGN_FLAGS = -SExternal.entitlements
External_CFLAGS = -I../include -O2 -Wno-unguarded-availability-new
External_LDFLAGS = -lkernelexternal

include $(THEOS_MAKE_PATH)/application.mk
