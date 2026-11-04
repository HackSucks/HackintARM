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
 * accesses are traced and answered from a small register file.  That is
 * deliberate: an access at these addresses means the guest really did reach
 * the device, so the trap, the syndrome decode, the ADT contract and the
 * register file can be validated before any GPU is involved.
 *
 * Guest contract (docs/lantern.md section 4.2): the GPU window's registers
 * are 32-bit and start at offset 0x1000; the IOSurface window's are 64-bit
 * and live at 0x1000-0x1030 of its own 64 KiB region.  Both windows are
 * trapped whole, so the offsets arrive unchanged.
 *
 * The register file here is a stand-in, not a model.  It does exactly three
 * things, so that the driver can get past probe and show what it does next:
 *
 *   - 0x1034 (binary version) echoes what the guest last wrote: the guest
 *     writes the version it wants and reads back what the host negotiated;
 *   - registers that only hold configuration (FIFO enable, length, start,
 *     interrupt mask, root page, base) read back what was written;
 *   - everything else reads as zero, as the core does for unhandled
 *     registers, and writes to it are ignored.
 *
 * Nothing here raises an interrupt or completes a command: a doorbell write
 * is traced and dropped.  Every access is traced with the guest PC, so the
 * first few lines of a boot are enough to name the kernel function that
 * made them (tools/kcsym.py).
 */
#include "gh.h"

/* Lines traced per device before only a periodic count is printed. */
#define LANTERN_TRACE_LIMIT     96u
#define LANTERN_TRACE_PERIOD    0x3ffu

#define LANTERN_REG_BASE        0x1000u

/* GPU window registers (32-bit), from docs/lantern.md section 4.2. */
#define GFX_FIFO_ENABLE         0x1000u
#define GFX_FIFO_LENGTH         0x1004u
#define GFX_FIFO_WRITTEN        0x1008u
#define GFX_FIFO_READ           0x100cu
#define GFX_FIFO_START          0x1010u
#define GFX_DISPLAY_IRQ_MASK    0x1014u
#define GFX_STAMP_IRQ_MASK      0x1018u		/* read-to-clear */
#define GFX_ROOT_PAGE           0x101cu
#define GFX_DOORBELL            0x1020u
#define GFX_RESUME_LO           0x1024u
#define GFX_RESUME_HI           0x1028u
#define GFX_FAULT_FLAG          0x102cu
#define GFX_BASE                0x1030u
#define GFX_VERSION             0x1034u
#define GFX_EFI_DISPLAY         0x1200u

/* One slot per 32-bit register in [0x1000, 0x1040). */
#define GFX_SHADOW_SLOTS        16u
/* One slot per 64-bit register in [0x1000, 0x1040). */
#define IOSFC_SHADOW_SLOTS      8u

struct lantern_dev {
	const char *name;
	u64 base;
	u32 reads;
	u32 writes;
};

static struct lantern_dev lantern_gfx   = { "gfx  ", GH_LANTERN_GFX_BASE,   0, 0 };
static struct lantern_dev lantern_iosfc = { "iosfc", GH_LANTERN_IOSFC_BASE, 0, 0 };

static u32 gfx_shadow[GFX_SHADOW_SLOTS];
static u64 iosfc_shadow[IOSFC_SHADOW_SLOTS];
static u32 lantern_version;
static u32 lantern_doorbells;

static struct lantern_dev *lantern_decode(u64 ipa, u32 *off)
{
	if (ipa >= GH_LANTERN_GFX_BASE &&
	    ipa < GH_LANTERN_GFX_BASE + GH_LANTERN_WINDOW_SIZE) {
		*off = (u32)(ipa - GH_LANTERN_GFX_BASE);
		return &lantern_gfx;
	}
	if (ipa >= GH_LANTERN_IOSFC_BASE &&
	    ipa < GH_LANTERN_IOSFC_BASE + GH_LANTERN_WINDOW_SIZE) {
		*off = (u32)(ipa - GH_LANTERN_IOSFC_BASE);
		return &lantern_iosfc;
	}
	return 0;
}

static const char *gfx_reg_name(u32 off)
{
	switch (off) {
	case GFX_FIFO_ENABLE:		return "FIFO_ENABLE";
	case GFX_FIFO_LENGTH:		return "FIFO_LENGTH";
	case GFX_FIFO_WRITTEN:		return "FIFO_WRITTEN";
	case GFX_FIFO_READ:		return "FIFO_READ";
	case GFX_FIFO_START:		return "FIFO_START";
	case GFX_DISPLAY_IRQ_MASK:	return "DISPLAY_IRQ_MASK";
	case GFX_STAMP_IRQ_MASK:	return "STAMP_IRQ_MASK";
	case GFX_ROOT_PAGE:		return "ROOT_PAGE";
	case GFX_DOORBELL:		return "DOORBELL";
	case GFX_RESUME_LO:		return "RESUME_LO";
	case GFX_RESUME_HI:		return "RESUME_HI";
	case GFX_FAULT_FLAG:		return "FAULT_FLAG";
	case GFX_BASE:			return "BASE";
	case GFX_VERSION:		return "VERSION";
	default:
		if (off >= GFX_EFI_DISPLAY)
			return "EFI_DISPLAY";
		if (off < LANTERN_REG_BASE)
			return "below-register-file";
		return "unknown";
	}
}

/* Registers that only hold what the guest wrote. */
static int gfx_is_storage(u32 off)
{
	switch (off) {
	case GFX_FIFO_ENABLE:
	case GFX_FIFO_LENGTH:
	case GFX_FIFO_START:
	case GFX_DISPLAY_IRQ_MASK:
	case GFX_ROOT_PAGE:
	case GFX_BASE:
		return 1;
	default:
		return 0;
	}
}

static int gfx_shadow_slot(u32 off)
{
	if (off < LANTERN_REG_BASE || (off & 3u))
		return -1;
	off = (off - LANTERN_REG_BASE) >> 2;
	return off < GFX_SHADOW_SLOTS ? (int)off : -1;
}

static int iosfc_shadow_slot(u32 off)
{
	if (off < LANTERN_REG_BASE || (off & 7u))
		return -1;
	off = (off - LANTERN_REG_BASE) >> 3;
	return off < IOSFC_SHADOW_SLOTS ? (int)off : -1;
}

/*
 * One line per access:
 *   lantern: gfx   rd  off 0x...1034 VERSION          size 4 val 0x... pc 0x...
 */
static void lantern_trace(struct lantern_dev *dev, int write, u32 off,
			  u32 size, u64 value, u64 pc, const char *name)
{
	gh_uart_puts("lantern: ");
	gh_uart_puts(dev->name);
	gh_uart_puts(write ? " wr  off " : " rd  off ");
	gh_uart_puthex(off);
	gh_uart_puts(" ");
	gh_uart_puts(name);
	gh_uart_puts(" size ");
	gh_uart_puthex(size);
	gh_uart_puts(" val ");
	gh_uart_puthex(value);
	gh_uart_puts(" pc ");
	gh_uart_puthex(pc);
	gh_uart_putc('\n');
}

static void lantern_count(struct lantern_dev *dev, int write)
{
	u32 n = write ? dev->writes : dev->reads;

	if (n >= LANTERN_TRACE_LIMIT && (n & LANTERN_TRACE_PERIOD) == 0) {
		gh_uart_puts("lantern: ");
		gh_uart_puts(dev->name);
		gh_uart_puts(write ? " writes so far " : " reads so far  ");
		gh_uart_puthex(n);
		gh_uart_putc('\n');
	}
}

u64 gh_lantern_mmio_read(u64 ipa, u32 size, u64 pc)
{
	u32 off = 0;
	struct lantern_dev *dev = lantern_decode(ipa, &off);
	const char *name = "register";
	u64 value = 0;
	int slot;

	if (!dev)
		return 0;

	if (dev == &lantern_gfx) {
		name = gfx_reg_name(off);
		if (off == GFX_VERSION) {
			value = lantern_version;
		} else if (gfx_is_storage(off) &&
			   (slot = gfx_shadow_slot(off)) >= 0) {
			value = gfx_shadow[slot];
		}
		/* STAMP_IRQ_MASK is read-to-clear; with no interrupt ever
		 * raised there is nothing pending to clear. */
	} else {
		slot = iosfc_shadow_slot(off);
		if (slot >= 0)
			value = iosfc_shadow[slot];
	}

	if (dev->reads < LANTERN_TRACE_LIMIT)
		lantern_trace(dev, 0, off, size, value, pc, name);
	else
		lantern_count(dev, 0);
	dev->reads++;
	return value;
}

void gh_lantern_mmio_write(u64 ipa, u32 size, u64 value, u64 pc)
{
	u32 off = 0;
	struct lantern_dev *dev = lantern_decode(ipa, &off);
	const char *name = "register";
	int slot;

	if (!dev)
		return;

	if (dev == &lantern_gfx) {
		name = gfx_reg_name(off);
		if (off == GFX_VERSION) {
			lantern_version = (u32)value;
		} else if (off == GFX_DOORBELL) {
			/* Nothing consumes the FIFO yet: say so once, then
			 * count, so a guest that spins on it is visible. */
			if (lantern_doorbells == 0)
				gh_log("lantern: first doorbell; no host to "
				       "service it yet\n");
			lantern_doorbells++;
		} else if (gfx_is_storage(off) &&
			   (slot = gfx_shadow_slot(off)) >= 0) {
			gfx_shadow[slot] = (u32)value;
		}
	} else {
		slot = iosfc_shadow_slot(off);
		if (slot >= 0)
			iosfc_shadow[slot] = value;
	}

	if (dev->writes < LANTERN_TRACE_LIMIT)
		lantern_trace(dev, 1, off, size, value, pc, name);
	else
		lantern_count(dev, 1);
	dev->writes++;
}
