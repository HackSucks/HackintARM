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
 * Why the transition happens here and not at Gatehouse entry
 * ----------------------------------------------------------
 * With the virtualization extensions enabled, the firmware itself runs at
 * EL2 (in VHE host mode on QEMU `virt`) and services its own interrupts
 * there.  Pulling UEFI down to EL1 mid-boot fights the firmware's live
 * exception state.  Instead Gatehouse runs at whatever EL the firmware uses,
 * and Trestle takes ownership of EL2 only at the final handoff, when Boot
 * Services are gone and nothing but XNU is left to run.  The same code path
 * works on hardware: the bootloader either is entered at EL2 or installs
 * Trestle from a firmware-provided EL2 context, then erets to XNU at EL1.
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

	/* Which exception level is actually active? */
	mrs	x9, CurrentEL
	lsr	x9, x9, #2
	cmp	x9, #2
	b.eq	.Lel2

	/* EL1: turn translation and caches off before touching TCR/TTBR. */
	mrs	x6, sctlr_el1
	bic	x6, x6, #0x1		/* M : MMU off */
	bic	x6, x6, #0x4		/* C : data cache off */
	bic	x6, x6, #(1 << 12)	/* I : instruction cache off */
	msr	sctlr_el1, x6
	isb

	tlbi	vmalle1
	dsb	ish
	isb
	b	.Lenter

.Lel2:
	/*
	 * EL2 is active.  With VHE (HCR_EL2.E2H==1) the firmware's live MMU
	 * and caches are SCTLR_EL2, so that is what has to be turned off;
	 * SCTLR_EL1 belongs to the guest and is only written for XNU.
	 */
	mrs	x6, sctlr_el2
	bic	x6, x6, #0x1		/* M */
	bic	x6, x6, #0x4		/* C */
	bic	x6, x6, #(1 << 12)	/* I */
	msr	sctlr_el2, x6
	isb

	tlbi	alle2
	dsb	ish
	isb

	/* The guest starts cold: no MMU, no caches.  start.s sets these. */
	msr	sctlr_el1, xzr
	isb
	tlbi	vmalls12e1
	dsb	ish
	isb

	/*
	 * Trestle's EL2 state.  Stage 2 is off for now (VM=0), so
	 * guest-physical == physical.  Physical IRQ/FIQ/SError are routed to
	 * EL1, FP/SIMD is not trapped, pointer authentication is enabled for
	 * EL1 (API/APK; without them every PAC instruction at EL1 is
	 * UNDEFINED), and the guest may read the physical counter and use the
	 * physical timer.
	 */
	mov	x6, #1
	lsl	x6, x6, #31		/* HCR_EL2.RW: EL1 is AArch64 */
	mov	x7, #3
	lsl	x7, x7, #40		/* HCR_EL2.{APK,API}: allow PAC at EL1 */
	orr	x6, x6, x7
	msr	hcr_el2, x6
	isb				/* E2H change takes effect here */
	msr	cptr_el2, xzr
	msr	hstr_el2, xzr
	mov	x6, #3			/* EL1PCTEN | EL1PCEN */
	msr	cnthctl_el2, x6
	msr	cntvoff_el2, xzr

	/* Anything that does trap to EL2 lands in Trestle's handler. */
	adrp	x6, gh_el2_vectors
	add	x6, x6, :lo12:gh_el2_vectors
	msr	vbar_el2, x6

	/* Trestle gets its own stack; the guest keeps the scratch one.
	 * SP_EL2 itself is only writable from EL3, so select it as the
	 * current stack pointer and set it with MOV SP. */
	adrp	x6, gh_el2_stack
	add	x6, x6, :lo12:gh_el2_stack
	add	x6, x6, #(16 * 1024)
	msr	spsel, #1
	mov	sp, x6

	/* Return to XNU at EL1h with DAIF masked and the scratch stack.
	 * An eret taken at EL2 uses ELR_EL2/SPSR_EL2; the target EL comes
	 * from the SPSR mode field. */
	msr	sp_el1, x2
	adr	x6, .Lenter
	msr	elr_el2, x6
	mov	x6, #0x3c5		/* EL1h, D|A|I|F */
	msr	spsr_el2, x6
	isb
	eret

.Lenter:
	/* XNU: x0 = boot_args physical address. */
	mov	x0, x20
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	br	x19
