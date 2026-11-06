/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LANTERN_TRANSPORT_H
#define LANTERN_TRANSPORT_H

#include <stdint.h>

/*
 * The Lantern mailbox: the only memory the guest's EL2 front-end and the
 * host PVG consumer share.  It is a single cache-coherent page that Gatehouse
 * places immediately above the guest's DRAM window; the host finds it by
 * scanning the machine's RAM for the magic, so no adapter has to be told a
 * guest-physical address or a RAM size out of band.
 *
 * The layout is fixed-width and architecture-independent: the guest side is
 * AArch64 EL2, the host side is whatever the GPU stack runs on (x86-64 Linux
 * today), and both map the same bytes.  It is not a C ABI to persist across
 * versions: abi_version and struct_size have to match exactly, and a mismatch
 * means the host refuses to attach rather than guess.
 *
 * Access rules:
 *   - the guest publishes a request by filling the request fields and then
 *     storing LANTERN_REQ_READY to `state` with release semantics;
 *   - the host publishes the answer by storing `result` and then
 *     LANTERN_REQ_DONE to `state` with release semantics;
 *   - the guest consumes it, stores LANTERN_REQ_EMPTY, and is the only side
 *     that writes EMPTY;
 *   - `host_ready` is set by the host once both PVG devices exist.  The guest
 *     waits for it before its first request and otherwise stays on its local
 *     register file, so a host that never comes up slows boot for one timeout
 *     instead of hanging it.
 */
#define LANTERN_MAILBOX_MAGIC   UINT64_C(0x4c414e5445524e32) /* "LANTERN2" */
#define LANTERN_ABI_VERSION     2u

#define LANTERN_REQ_EMPTY       0u
#define LANTERN_REQ_READY       1u
#define LANTERN_REQ_DONE        2u

#define LANTERN_DEVICE_GFX      0u
#define LANTERN_DEVICE_IOSFC    1u

#define LANTERN_IRQ_GFX         (1u << 0)
#define LANTERN_IRQ_IOSFC       (1u << 1)

struct lantern_mailbox {
	/* Written once by the guest; read once by the host to attach. */
	uint64_t magic;
	uint32_t abi_version;
	uint32_t struct_size;
	uint64_t self_phys;      /* this page's guest-physical address */
	uint64_t ram_base;       /* guest DRAM window the host must map */
	uint64_t ram_size;

	/* Request. */
	uint32_t state;
	uint32_t device;
	uint32_t write;
	uint32_t reg_size;
	uint64_t offset;
	uint64_t value;

	/* Answer. */
	uint64_t result;

	/* Asynchronous state. */
	uint32_t irq_pending;    /* host -> guest, LANTERN_IRQ_* bits */
	uint32_t host_ready;     /* host -> guest, set once devices exist */
};

_Static_assert(sizeof(struct lantern_mailbox) == 88,
	       "Lantern mailbox ABI changed");

#endif
