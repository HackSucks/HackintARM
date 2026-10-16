# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

# Gatehouse - HackintARM ARM64 bootloader (UEFI application)
#
# Builds a freestanding PE32+ EFI application with clang + lld-link.
# No EDK2 / gnu-efi tree required.

TARGET   := BOOTAA64.EFI
CC       := clang
LD       := lld-link
OBJCOPY  := llvm-objcopy

TARGETFLAGS := --target=aarch64-unknown-windows
CFLAGS  := $(TARGETFLAGS) -ffreestanding -fno-stack-protector -fno-builtin \
           -fshort-wchar -mno-red-zone -O2 -g -Wall -Wextra \
           -Wno-unused-parameter -Iinclude -ffunction-sections -fdata-sections \
           -march=armv8-a+pauth

ifdef STALL
CFLAGS += -DGH_ATTACH_STALL_MS=$(STALL)
endif

SRCS := src/main.c src/lib.c src/uart.c src/macho.c src/bootargs.c src/fixups.c src/patch.c
OBJS := $(SRCS:.c=.o) src/jump.o
HDRS := $(wildcard include/*.h)

LDFLAGS := /machine:arm64 /subsystem:efi_application /entry:efi_main \
           /nodefaultlib /out:$(TARGET) /debug:none /opt:noref

.PHONY: all clean
all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS)
	@echo "built $(TARGET):"
	@file $(TARGET)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

src/jump.o: src/jump.S
	$(CC) $(TARGETFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
