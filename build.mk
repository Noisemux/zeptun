PROJECT := zeptun
ZIG ?= zig
OPTIMIZE ?= fast
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
INCDIR ?= $(PREFIX)/include
CONFDIR ?= /etc/zeptun
OUTDIR := zig-out
ZIGFLAGS ?=

ifneq ($(TARGET),)
	ZIGFLAGS += -Dtarget=$(TARGET)
endif
ifneq ($(CPU),)
	ZIGFLAGS += -Dcpu=$(CPU)
endif

ifeq ($(REV_ID),)
	ifneq (,$(wildcard .rev-id))
		REV_ID := $(shell cat .rev-id)
	endif
	ifeq ($(REV_ID),)
		REV_ID := $(shell git rev-parse --short HEAD 2> /dev/null)
	endif
	ifeq ($(REV_ID),)
		REV_ID := unknown
	endif
endif

WINTUN_ARCH ?= amd64
ANDROID_ABIS ?= armeabi-v7a arm64-v8a x86 x86_64
APPLE_PLATFORMS ?= iphoneos iphonesimulator macosx
