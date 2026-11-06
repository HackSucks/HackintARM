# SPDX-License-Identifier: GPL-2.0-or-later

CC ?= cc
PKG_CONFIG ?= pkg-config
PACKAGE ?= reims-vgpu
TARGET ?= lantern-host

ifeq ($(shell $(PKG_CONFIG) --exists $(PACKAGE) 2>/dev/null && echo yes),)
$(error reims-vgpu pkg-config package not found; set PKG_CONFIG_PATH to its lib/pkgconfig directory)
endif

CFLAGS += -std=c11 -O2 -g -Wall -Wextra -Werror
CFLAGS += $(shell $(PKG_CONFIG) --cflags $(PACKAGE))
LDLIBS += $(shell $(PKG_CONFIG) --libs $(PACKAGE))

.PHONY: all clean
all: $(TARGET) lantern-probe


$(TARGET): consumer.c shared_ram.c consumer.h ../include/transport.h
	$(CC) $(CFLAGS) -I../include consumer.c shared_ram.c $(LDFLAGS) $(LDLIBS) -o $@

lantern-probe: probe.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET) lantern-probe
