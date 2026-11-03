/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 HackintARM contributors */

/*
 * gatehouse/src/lantern.c - the guest-facing side of Lantern.
 *
 * Lantern translates VMApple's paravirtualised GPU protocol into a real GPU.
 * Stage 2 leaves the GPU and IOSurface windows unmapped, so every guest
 * access to them arrives here through gh_el2_trap_c().  This file is the
 * seam between that trap layer and the PVG device model.
 *
 * The device model itself is not in this image: reims-vgpu needs Vulkan and
 * an OS, neither of which exists at EL2.  It runs on the host behind a
 * transport, and this file becomes the front-end that turns a trapped
 * access into a transport request.  Until that transport is wired up, the
 * accesses are reported and answered from a tiny register file.  That is
 * deliberate: an access at these addresses means the guest really did reach
 * the device, so the trap, the syndrome decode, the ADT contract and the
 * register file can be validated before any GPU is involved.
 *
 * The one register with behaviour here is 0x1034, the binary version.  The
 * guest writes the version it wants and reads back what the host negotiated;
 * echoing it is enough for the driver to move on to the root page and FIFO
 * registers, which is what the bring-up wants to see.
 *
 * Guest contract (docs/testing.md section 6): registers are 32-bit, the GPU
 * window's register file starts at offset 0x1000, and the IOSurface window's
 * at 0x1000 in its own 64 KiB region.  Both windows are trapped whole, so the
 * offsets arrive unchanged.
 */
#include "gh.h"

#define LANTERN_TRACE_LIMIT     12
#define LANTERN_REG_BASE        0x1000u
#define LANTERN_REG_VERSION     0x1034u

/* The PVG register file.  Only the version is stateful so far. */
static u32 lantern_version;
static u32 lantern_reads;
static u32 lantern_writes;

static int lantern_in_window(u64 ipa, u64 base)
{
	return ipa >= base && ipa < base + GH_LANTERN_WINDOW_SIZE;
}

static void lantern_log(u64 ipa, const char *what, u64 value)
{
	gh_loghex(what, ipa);
	if (value)
		gh_loghex("lantern: value  ", value);
}

u64 gh_lantern_mmio_read(u64 ipa, u32 size)
{
	u32 off = (u32)(ipa - GH_LANTERN_GFX_BASE);
	u64 value = 0;

	if (lantern_in_window(ipa, GH_LANTERN_GFX_BASE) &&
	    off == LANTERN_REG_VERSION)
		value = lantern_version;

	if (lantern_reads < LANTERN_TRACE_LIMIT) {
		gh_loghex("lantern: read off ", off);
		gh_loghex("lantern: read     ", value);
	} else if ((lantern_reads & 0x3ffu) == 0) {
		gh_loghex("lantern: reads    ", lantern_reads);
	}
	lantern_reads++;
	return value;
}

void gh_lantern_mmio_write(u64 ipa, u32 size, u64 value)
{
	u32 off = (u32)(ipa - GH_LANTERN_GFX_BASE);

	if (lantern_in_window(ipa, GH_LANTERN_GFX_BASE) &&
	    off == LANTERN_REG_VERSION) {
		lantern_version = (u32)value;
		gh_loghex("lantern: version  ", lantern_version);
	}

	if (lantern_writes < LANTERN_TRACE_LIMIT)
		lantern_log(ipa, "lantern: write    ", value);
	else if ((lantern_writes & 0x3ffu) == 0)
		gh_loghex("lantern: writes   ", lantern_writes);
	lantern_writes++;
}
