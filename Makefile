TARGET := iphone:clang:latest:15.0
ARCHS := arm64
INSTALL_TARGET_PROCESSES = pool

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NinjaBypass

NinjaBypass_FILES = Tweak.xm
NinjaBypass_CFLAGS = -fobjc-arc -O2 -Wno-unused-function
NinjaBypass_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
