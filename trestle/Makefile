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

SRCS := src/main.c src/platform.c src/nvram.c
OBJS := $(SRCS:.c=.o)
HDRS := $(wildcard include/*.h)

.PHONY: all clean test
all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "built $@:"
	@ls -l $@

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Host-side model tests (nvram.c is freestanding and links against the host
# libc without pulling any machine dependency).
test: tests/nvram_test
	./tests/nvram_test

tests/nvram_test: tests/nvram_test.c src/nvram.c $(HDRS)
	$(CC) -O2 -g -Wall -Wextra -Iinclude tests/nvram_test.c src/nvram.c -o $@

clean:
	rm -f $(OBJS) $(LIB) tests/nvram_test
