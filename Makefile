TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = NinjaBypass
NinjaBypass_FILES = NinjaBypass.m
NinjaBypass_CFLAGS = -fobjc-arc -O2 -fvisibility=hidden \
                     -Wno-unused-function -Wno-deprecated-declarations
NinjaBypass_FRAMEWORKS = Foundation UIKit
NinjaBypass_LDFLAGS = -Wl,-undefined,dynamic_lookup \
                      -Wl,-install_name,@rpath/libNinjaBypass.dylib

include $(THEOS_MAKE_PATH)/library.mk
