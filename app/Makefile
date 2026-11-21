TARGET := iphone:latest:15.0
ARCHS := arm64 arm64e
THEOS_PACKAGE_SCHEME ?= rootless

APPLICATION_NAME = External

External_FILES = src/ExternalApp.m src/Engine.m src/RootViewController.m
External_FRAMEWORKS = UIKit
External_LIBRARIES = kernelexternal
External_CODESIGN_FLAGS = -SExternal.entitlements
External_CFLAGS = -I../include -O2

include $(THEOS_MAKE_PATH)/application.mk
