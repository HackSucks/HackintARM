# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

# Trestle - HackintARM platform layer (freestanding, machine-portable)
#
# Builds a freestanding aarch64 static library.  Nothing here links a C
# library or assumes a particular machine; the machine description is passed
# in at run time (see include/trestle.h).

LIB      := libtrestle.a
CC       := clang
AR       := llvm-ar

TARGETFLAGS := --target=aarch64-none-elf
CFLAGS  := $(TARGETFLAGS) -ffreestanding -fno-stack-protector -fno-builtin \
           -mno-red-zone -O2 -g -Wall -Wextra -Werror -Wno-unused-parameter \
           -Iinclude -ffunction-sections -fdata-sections -march=armv8-a+pauth

SRCS := src/main.c src/boot.c src/adt.c src/machines.c src/platform.c \
        src/platform_nodes.c src/nvram.c src/rtc.c src/pmgr.c src/panic.c \
        src/aprr.c
OBJS := $(SRCS:.c=.o)
HDRS := $(wildcard include/*.h)

# Everything except the entry point is machine-independent and host-buildable,
# which is what the model tests link.
MODEL_SRCS := src/boot.c src/adt.c src/machines.c src/platform.c \
              src/platform_nodes.c src/nvram.c src/rtc.c src/pmgr.c \
              src/panic.c src/aprr.c

.PHONY: all clean test
all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "built $@:"
	@ls -l $@

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Host-side model tests.  The device models, the tree builder and the machine
# descriptions are freestanding but link against the host libc without pulling
# in a machine dependency: only src/main.c reads the machine's clock, and the
# tests supply their own.
test: tests/nvram_test tests/adt_test
	./tests/nvram_test
	./tests/adt_test

tests/nvram_test: tests/nvram_test.c src/nvram.c src/adt.c $(HDRS)
	$(CC) -O2 -g -Wall -Wextra -Iinclude tests/nvram_test.c src/nvram.c \
	      src/adt.c -o $@

# Builds the whole tree for the bring-up machine, checks the properties the
# boot path depends on, exercises the device models' MMIO, and (given a path)
# writes the serialised tree out so tools/adt_diff.py can compare it with
# gatehouse/dt/build_adt.py's.
tests/adt_test: tests/adt_test.c $(MODEL_SRCS) $(HDRS)
	$(CC) -O2 -g -Wall -Wextra -Iinclude tests/adt_test.c $(MODEL_SRCS) -o $@

clean:
	rm -f $(OBJS) $(LIB) tests/nvram_test tests/adt_test
