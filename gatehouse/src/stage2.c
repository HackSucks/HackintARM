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
 * Nothing here names a machine.  The RAM window comes from memory.c, which
 * read the firmware map, so the same map describes QEMU with any -m, an
 * Apple Silicon machine, or a board.  RAM is Normal and everything else is
 * Device-nGnRnE; RAM edges get 4 KiB pages so no byte outside the window is
 * ever reported as cacheable memory.
 *
 * Granule: 4 KiB.  With T0SZ=25 the walk starts at level 1 and covers a
 * 39-bit IPA (512 GiB), which is every machine this loader targets.  Whole
 * 1 GiB blocks use block descriptors; a block that only partly covers RAM,
 * or that holds a Lantern window, gets an L2 table of 2 MiB blocks, and the
 * 2 MiB chunks that hold a window or a RAM edge get L3 tables.  The window
 * addresses come from the ADT (lantern.c), so a different machine description
 * moves the holes without touching this file.
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

#define S2_ENTRIES     512
#define S2_PAGE_4K     (1ull << 12)
#define S2_BLOCK_2M    (1ull << 21)
#define S2_BLOCK_1G    (1ull << 30)

/* A LANTERN_BLOCK is only ever one 2 MiB chunk, and at most two RAM edges
 * need an L2 and two more L3 tables.  The pools are generous because a
 * missing table would silently drop memory; the builder logs if it runs out
 * instead of corrupting a neighbour. */
#define S2_MAX_L2      8
#define S2_MAX_L3      16

static u64 s2_l1[S2_ENTRIES] __attribute__((aligned(4096)));
static u64 s2_l2_pool[S2_MAX_L2][S2_ENTRIES] __attribute__((aligned(4096)));
static u64 s2_l3_pool[S2_MAX_L3][S2_ENTRIES] __attribute__((aligned(4096)));
static u32 s2_l2_used;
static u32 s2_l3_used;

static u64 s2_block(u64 pa, u64 attr)
{
	return pa | attr | S2_DESC_VALID;
}

static u64 s2_page(u64 pa, u64 attr)
{
	return pa | attr | S2_DESC_PAGE;
}

static u64 *s2_alloc_l2(void)
{
	if (s2_l2_used >= S2_MAX_L2)
		return 0;
	return s2_l2_pool[s2_l2_used++];
}

static u64 *s2_alloc_l3(void)
{
	if (s2_l3_used >= S2_MAX_L3)
		return 0;
	return s2_l3_pool[s2_l3_used++];
}

static int s2_in_ram(u64 pa, u64 base, u64 top)
{
	return pa >= base && pa < top;
}

/* Does [lo, hi) touch either Lantern window? */
static int s2_lantern_hit(u64 lo, u64 hi)
{
	u32 w;

	for (w = 0; w < 2; w++) {
		u64 base = gh_lantern_window_base(w);
		u64 end = base + gh_lantern_window_size(w);

		if (base && lo < end && hi > base)
			return 1;
	}
	return 0;
}

static int s2_is_lantern(u64 pa)
{
	return s2_lantern_hit(pa, pa + 1);
}

/* Fill one 2 MiB chunk with 4 KiB pages: RAM is Normal, the Lantern windows
 * are absent, everything else is Device.  Used at RAM edges and for the
 * Lantern chunk, where block granularity is too coarse. */
static void s2_fill_pages(u64 *l3, u64 chunk, u64 base, u64 top, u64 dev,
    u64 ram)
{
	u32 i;

	for (i = 0; i < S2_ENTRIES; i++) {
		u64 pa = chunk + (u64)i * S2_PAGE_4K;

		if (s2_is_lantern(pa))
			l3[i] = 0;
		else if (s2_in_ram(pa, base, top))
			l3[i] = s2_page(pa, ram);
		else
			l3[i] = s2_page(pa, dev);
	}
}

static void s2_build_l2(u64 *l2, u64 blk, u64 base, u64 top, u64 dev,
    u64 ram)
{
	u32 i;

	for (i = 0; i < S2_ENTRIES; i++) {
		u64 chunk = blk + (u64)i * S2_BLOCK_2M;
		u64 end = chunk + S2_BLOCK_2M;

		if (s2_lantern_hit(chunk, end)) {
			u64 *l3 = s2_alloc_l3();

			if (!l3) {
				gh_log("stage 2: out of L3 tables\n");
				l2[i] = 0;
				continue;
			}
			s2_fill_pages(l3, chunk, base, top, dev, ram);
			l2[i] = (u64)l3 | S2_DESC_TABLE;
		} else if (base <= chunk && end <= top) {
			l2[i] = s2_block(chunk, ram);
		} else if (end <= base || chunk >= top) {
			l2[i] = s2_block(chunk, dev);
		} else {
			u64 *l3 = s2_alloc_l3();

			if (!l3) {
				gh_log("stage 2: out of L3 tables\n");
				l2[i] = 0;
				continue;
			}
			s2_fill_pages(l3, chunk, base, top, dev, ram);
			l2[i] = (u64)l3 | S2_DESC_TABLE;
		}
	}
}

void gh_stage2_init(void)
{
	const u64 dev = S2_AF | S2_AP_RW | S2_MEMATTR(S2_MEMATTR_DEVICE);
	const u64 ram = S2_AF | S2_AP_RW | S2_SH_INNER |
			S2_MEMATTR(S2_MEMATTR_NORMAL);
	u64 base = gh_memory_base();
	u64 top = gh_memory_top();
	u64 i;
	u64 vtcr;
	u64 hcr;

	if (!base || top <= base) {
		gh_log("stage 2: no RAM window, refusing to map\n");
		for (;;)
			__asm__ volatile("wfi");
	}
	if (top > (1ull << 39)) {
		gh_log("stage 2: RAM above the 39-bit IPA, clamping\n");
		top = 1ull << 39;
	}

	/* Identity map for the whole IPA: devices by default.  RAM blocks are
	 * overwritten below.  There is no per-machine address table. */
	for (i = 0; i < S2_ENTRIES; i++)
		s2_l1[i] = s2_block(i * S2_BLOCK_1G, dev);

	/*
	 * Whole 1 GiB blocks of RAM stay 1 GiB descriptors.  A block that only
	 * partly covers RAM, or that contains a Lantern window, gets a 2 MiB
	 * table so exactly the window bytes are absent and only real memory is
	 * Normal.  Every other block stays the Device block set above.
	 */
	if (base < top) {
		u64 first = base / S2_BLOCK_1G;
		u64 last = (top - 1) / S2_BLOCK_1G;

		for (i = first; i <= last; i++) {
			u64 blk = i * S2_BLOCK_1G;

			if (base <= blk && blk + S2_BLOCK_1G <= top &&
			    !s2_lantern_hit(blk, blk + S2_BLOCK_1G)) {
				s2_l1[i] = s2_block(blk, ram);
			} else {
				u64 *l2 = s2_alloc_l2();

				if (!l2) {
					gh_log("stage 2: out of L2 tables\n");
					continue;
				}
				s2_build_l2(l2, blk, base, top, dev, ram);
				s2_l1[i] = (u64)l2 | S2_DESC_TABLE;
			}
		}
	}

	/* Windows outside the RAM range still need their own block table; the
	 * lanes above only visit RAM blocks. */
	for (i = 0; i < S2_ENTRIES; i++) {
		u64 blk = i * S2_BLOCK_1G;
		u64 *l2;

		if (!s2_lantern_hit(blk, blk + S2_BLOCK_1G))
			continue;
		if ((s2_l1[i] & 3u) == S2_DESC_TABLE)
			continue;
		l2 = s2_alloc_l2();
		if (!l2) {
			gh_log("stage 2: out of L2 tables for Lantern\n");
			continue;
		}
		s2_build_l2(l2, blk, base, top, dev, ram);
		s2_l1[i] = (u64)l2 | S2_DESC_TABLE;
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
	gh_loghex("stage 2 ram     : ", base);
	gh_loghex("stage 2 ram top : ", top);
	gh_loghex("stage 2 window  : ", gh_lantern_window_base(GH_LANTERN_GFX));
	gh_loghex("stage 2 window  : ", gh_lantern_window_base(GH_LANTERN_IOSFC));
}
