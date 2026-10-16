/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 HackintARM contributors */

/*
 * gatehouse/src/jump.S - leave UEFI and hand control to XNU.
 *
 *   gh_jump_to_kernel(entry, boot_args_pa, stack_top, clean_base, clean_len)
 *     x0 = kernel entry (physical)
 *     x1 = boot_args  (physical)
 *     x2 = scratch stack top
 *     x3 = region to flush from (the loaded kernel image)
 *     x4 = region length
 *
 * Why we enter the kernel with translation disabled
 * -------------------------------------------------
 * XNU's start.s programs TCR_EL1 itself (MOV64 x1, TCR_EL1_BOOT) and then
 * keeps executing *before* it invalidates the TLB and installs its own
 * translation tables.  UEFI hands us a 4K-granule identity map; XNU's
 * TCR_EL1_BOOT selects a 16K granule.  Writing TCR_EL1 while translation is
 * enabled therefore reinterprets the active TTBR0 with the wrong granule and
 * the next instruction fetch translation-faults (observed as a level-1
 * translation abort at common_start+4).
 *
 * iBoot avoids this by already being configured the way XNU expects.  Since we
 * cannot know the firmware's granule, we instead hand XNU a clean, translation
 * -off machine: start.s builds its bootstrap tables and turns the MMU on
 * itself, so nothing between entry and its own `msr SCTLR_EL1` depends on an
 * identity mapping existing.
 *
 * This is exactly the "bare metal" state a real SoC bootloader can arrange,
 * and it keeps the loader free of any knowledge of XNU's page-table layout.
 */
	.text
	.globl gh_jump_to_kernel
gh_jump_to_kernel:
	msr	daifset, #0xf

	mov	x19, x0			/* entry */
	mov	x20, x1			/* boot_args */
	mov	sp, x2			/* scratch stack (physical) */

	/* Flush everything we wrote (kernel image, boot_args, device tree)
	 * to the point of coherency: with translation off, all accesses are
	 * non-cacheable, so the kernel must observe our stores in memory. */
	mrs	x7, ctr_el0
	ubfx	x7, x7, #16, #4		/* CTR_EL0.DminLine */
	mov	x8, #4
	lsl	x7, x8, x7		/* x7 = data cache line size */
	sub	x8, x7, #1		/* x8 = line mask */
	bic	x3, x3, x8		/* start, rounded down */
	add	x5, x3, x4		/* end = start + length */
	add	x5, x5, x8
	bic	x5, x5, x8		/* end, rounded up */
1:	dc	civac, x3
	add	x3, x3, x7
	cmp	x3, x5
	b.lo	1b
	dsb	ish

	/* Drop any stale instruction cache lines for the code we loaded. */
	ic	iallu
	dsb	ish
	isb

	/* Turn translation and caches off before touching TCR/TTBR. */
	mrs	x6, sctlr_el1
	bic	x6, x6, #0x1		/* M : MMU off */
	bic	x6, x6, #0x4		/* C : data cache off */
	bic	x6, x6, #(1 << 12)	/* I : instruction cache off */
	msr	sctlr_el1, x6
	isb

	tlbi	vmalle1
	dsb	ish
	isb

	/* XNU: x0 = boot_args physical address. */
	mov	x0, x20
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr

	br	x19
