/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LANTERN_HOST_CONSUMER_H
#define LANTERN_HOST_CONSUMER_H

#include <reims_vgpu.h>
#include "transport.h"

/* Platform adapters provide a coherent mailbox, guest RAM mapping and any
 * file handles required by reims-vgpu's memory-map implementation. */
struct lantern_host_transport {
	volatile struct lantern_mailbox *mailbox;
	const RvgMemoryMap *memory_map;
	const RvgMemoryRangeFile *memory_files;
};

int lantern_host_consume(const struct lantern_host_transport *transport);

#endif
