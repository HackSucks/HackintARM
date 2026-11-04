/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 HackintARM contributors */

/*
 * gatehouse/src/stage2.c - the stage-2 map Trestle runs the guest under.
 *
 * XNU is a guest now: it runs at EL1 with its own stage-1 tables, and every
 * intermediate physical address it produces goes through Trestle's stage 2.
 * For bring-up the map is the identity map -- the guest sees the physical
 * addresses it would see on the real machine -- with two deliberate holes:
 * Lantern's GPU and IOSurface windows, which fault to Trestle instead of
 * reaching memory.
 *
 * The holes are the point.  Those are the device's real AVP addresses; on
 * QEMU `virt` nothing else claims them, so a fault means the guest has
 * reached the device and Trestle's front-end gets to answer it.  The rest of
 * the PCIe MMIO window stays mapped, so QEMU's BAR placement is unaffected.
 *
 * Granule: 4 KiB.  With T0SZ=25 the walk starts at level 1 and covers a
 * 39-bit IPA, which is more than the 4 GiB this machine has.  The device
 * region below 1 GiB uses 2 MiB blocks, except the one block that contains
 * the two windows, which gets a 4 KiB table so only the windows are absent.
 * RAM is three 1 GiB blocks.
 */
#include "gh.h"

#define S2_DESC_VALID  0x1ull
#define S2_DESC_TABLE  0x3ull
/* A level-3 entry is a *page* descriptor, bits [1:0] = 0b11.  0b01 is a
 * block descriptor, which is only legal at levels 1 and 2; at level 3 it is
 * a reserved encoding and faults like an unmapped page. */
#define S2_DESC_PAGE   0x3ull
#define S2_AF          (1ull << 10)
#define S2_SH_INNER    (3ull << 8)
#define S2_AP_RW       (3ull << 6)
/*
 * Stage 2 carries its memory attributes in the descriptor itself, in
 * MemAttr[3:0] (descriptor bits [5:2]).  MAIR_EL2 is not consulted for
 * stage-2 translations.  The encoding is not MAIR's: 0b0000 is
 * Device-nGnRnE, and 0b1111 is Normal, Outer/Inner write-back.
 */
#define S2_MEMATTR(idx) ((u64)(idx) << 2)

#define S2_MEMATTR_DEVICE 0x0ull
#define S2_MEMATTR_NORMAL 0xfull

/* IPA layout of the bring-up machine (see gatehouse/dt/build_adt.py). */
#define GH_DEVICE_BASE 0x00000000ull
#define GH_RAM_BASE    0x40000000ull
#define GH_RAM_SIZE    0x0c0000000ull	/* 3 GiB, 0x40000000..0x100000000 */

#define S2_ENTRIES     512
#define S2_BLOCK_2M    (1ull << 21)
#define S2_BLOCK_1G    (1ull << 30)

static u64 s2_l1[S2_ENTRIES] __attribute__((aligned(4096)));
static u64 s2_l2_dev[S2_ENTRIES] __attribute__((aligned(4096)));
static u64 s2_l3_lantern[S2_ENTRIES] __attribute__((aligned(4096)));

static u64 s2_block(u64 pa, u64 attr)
{
	return pa | attr | S2_DESC_VALID;
}

static u64 s2_page(u64 pa, u64 attr)
{
	return pa | attr | S2_DESC_PAGE;
}

void gh_stage2_init(void)
{
	const u64 lantern_block = GH_LANTERN_GFX_BASE & ~(S2_BLOCK_2M - 1);
	const u64 dev = S2_AF | S2_AP_RW | S2_MEMATTR(S2_MEMATTR_DEVICE);
	const u64 ram = S2_AF | S2_AP_RW | S2_SH_INNER |
			S2_MEMATTR(S2_MEMATTR_NORMAL);
	u64 i;
	u64 vtcr;
	u64 hcr;

	/* 0..1 GiB: every 2 MiB block of device space, by default. */
	for (i = 0; i < S2_ENTRIES; i++)
		s2_l2_dev[i] = s2_block(GH_DEVICE_BASE + i * S2_BLOCK_2M, dev);

	/* The block holding both Lantern windows: 4 KiB pages, so exactly the
	 * windows are absent and the rest of that 2 MiB stays usable. */
	for (i = 0; i < S2_ENTRIES; i++) {
		u64 pa = lantern_block + i * 4096;

		if (pa >= GH_LANTERN_GFX_BASE &&
		    pa < GH_LANTERN_IOSFC_BASE + GH_LANTERN_WINDOW_SIZE)
			s2_l3_lantern[i] = 0;
		else
			s2_l3_lantern[i] = s2_page(pa, dev);
	}
	s2_l2_dev[(lantern_block >> 21) & 0x1ff] =
	    (u64)s2_l3_lantern | S2_DESC_TABLE;

	s2_l1[0] = (u64)s2_l2_dev | S2_DESC_TABLE;

	/* RAM: three 1 GiB blocks, normal memory. */
	for (i = 0; i < GH_RAM_SIZE / S2_BLOCK_1G; i++) {
		u64 pa = GH_RAM_BASE + i * S2_BLOCK_1G;

		s2_l1[(pa >> 30) & 0x1ff] = s2_block(pa, ram);
	}

	/*
	 * T0SZ=25 (39-bit IPA), SL0=1 (level 1), WB-walk caches, inner
	 * shareable, 4 KiB granule, 40-bit physical size.  Bit 31 is the
	 * RES1 bit Linux calls VTCR_EL2_RES1; bit 23 is not RES1 here.
	 */
	vtcr = 25ull |
	       (1ull << 6) |		/* SL0 */
	       (1ull << 8) |		/* IRGN0: WB WA */
	       (1ull << 10) |		/* ORGN0: WB WA */
	       (3ull << 12) |		/* SH0: inner shareable */
	       (0ull << 14) |		/* TG0: 4 KiB */
	       (2ull << 16) |		/* PS: 40-bit */
	       (1ull << 31);		/* RES1 */

	__asm__ volatile("msr vttbr_el2, %0\n"
			 "msr vtcr_el2, %1\n"
			 "isb\n"
			 "tlbi vmalls12e1is\n"
			 "dsb ish\n"
			 "isb\n"
			 :
			 : "r"((u64)s2_l1), "r"(vtcr)
			 : "memory");

	/* Last: from here every EL1/EL0 access is translated. */
	__asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
	hcr |= 1ull;			/* HCR_EL2.VM */
	__asm__ volatile("msr hcr_el2, %0\n"
			 "isb\n"
			 :
			 : "r"(hcr)
			 : "memory");

	gh_loghex("stage 2         : ", (u64)s2_l1);
	gh_loghex("stage 2 vtcr    : ", vtcr);
	gh_loghex("stage 2 windows : ", GH_LANTERN_GFX_BASE);
}
