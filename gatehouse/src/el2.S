/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 HackintARM contributors */

/*
 * gatehouse/src/el2.S - Trestle's EL2 shell.
 *
 * Trestle owns EL2 while XNU runs at EL1.  The transition itself lives in
 * jump.S, next to the cache maintenance and the XNU entry path; this file
 * holds the part that has to stay resident afterwards:
 *
 *   - the EL2 vector table;
 *   - the lower-EL synchronous handler, which is where HVC/SMC calls from
 *     XNU land (PSCI, Apple's 0xc100 platform calls, and later real traps);
 *   - a diagnostic dead end for everything that is not expected yet.
 *
 * The EL2 stage-1 MMU is off after the handoff, so this code runs on physical
 * addresses (V=P for the boot image) and needs no page tables of its own.
 */

	.text

/*
 * VBAR_EL2 requires 2 KiB alignment; each of the 16 entries is 128 bytes.
 *
 * Trestle runs with HCR_EL2.E2H == 0, so the offset groups are the plain
 * (non-VHE) ones:
 *
 *   0x000  current EL with SP_EL0   (sync/IRQ/FIQ/SError)
 *   0x200  current EL with SP_ELx
 *   0x400  lower EL using AArch64
 *   0x600  lower EL using AArch32
 *
 * XNU runs at EL1/AArch64, so its HVC/SMC traps arrive at 0x400.  Do not
 * mistake this for VHE's layout, where the lower-EL group is at 0x200.
 */
	.p2align 11
	.globl gh_el2_vectors
gh_el2_vectors:
	.p2align 7
	b	gh_el2_unexpected	/* 0x000 current EL, SP0, sync */
	.p2align 7
	b	gh_el2_unexpected	/* 0x080 current EL, SP0, IRQ */
	.p2align 7
	b	gh_el2_unexpected	/* 0x100 current EL, SP0, FIQ */
	.p2align 7
	b	gh_el2_unexpected	/* 0x180 current EL, SP0, SError */
	.p2align 7
	b	gh_el2_unexpected	/* 0x200 current EL, SPx, sync */
	.p2align 7
	b	gh_el2_unexpected	/* 0x280 current EL, SPx, IRQ */
	.p2align 7
	b	gh_el2_unexpected	/* 0x300 current EL, SPx, FIQ */
	.p2align 7
	b	gh_el2_unexpected	/* 0x380 current EL, SPx, SError */
	.p2align 7
	b	gh_el2_sync		/* 0x400 lower EL AArch64, sync */
	.p2align 7
	b	gh_el2_unexpected	/* 0x480 lower EL AArch64, IRQ */
	.p2align 7
	b	gh_el2_unexpected	/* 0x500 lower EL AArch64, FIQ */
	.p2align 7
	b	gh_el2_unexpected	/* 0x580 lower EL AArch64, SError */
	.p2align 7
	b	gh_el2_unexpected	/* 0x600 lower EL AArch32, sync */
	.p2align 7
	b	gh_el2_unexpected	/* 0x680 lower EL AArch32, IRQ */
	.p2align 7
	b	gh_el2_unexpected	/* 0x700 lower EL AArch32, FIQ */
	.p2align 7
	b	gh_el2_unexpected	/* 0x780 lower EL AArch32, SError */

/*
 * Synchronous trap from the guest.  The guest's general-purpose registers are
 * not banked, so save every one the C ABI may clobber plus LR, hand the C
 * handler the syndrome, the preferred return address and a pointer to the
 * saved frame, then resume the guest at the address it returns.
 *
 * Frame (16-byte aligned, 176 bytes):
 *   0    x0      x1      ...   x18     x29     x30
 *   ^ regs[0] is the value the handler leaves as the guest's x0.
 */
gh_el2_sync:
	sub	sp, sp, #176
	stp	x0, x1, [sp, #0]
	stp	x2, x3, [sp, #16]
	stp	x4, x5, [sp, #32]
	stp	x6, x7, [sp, #48]
	stp	x8, x9, [sp, #64]
	stp	x10, x11, [sp, #80]
	stp	x12, x13, [sp, #96]
	stp	x14, x15, [sp, #112]
	stp	x16, x17, [sp, #128]
	stp	x18, x29, [sp, #144]
	str	x30, [sp, #160]

	mrs	x0, esr_el2
	mrs	x1, elr_el2
	mov	x2, sp
	bl	gh_el2_trap_c
	msr	elr_el2, x0

	ldp	x0, x1, [sp, #0]
	ldp	x2, x3, [sp, #16]
	ldp	x4, x5, [sp, #32]
	ldp	x6, x7, [sp, #48]
	ldp	x8, x9, [sp, #64]
	ldp	x10, x11, [sp, #80]
	ldp	x12, x13, [sp, #96]
	ldp	x14, x15, [sp, #112]
	ldp	x16, x17, [sp, #128]
	ldp	x18, x29, [sp, #144]
	ldr	x30, [sp, #160]
	add	sp, sp, #176
	eret

gh_el2_unexpected:
	mrs	x0, esr_el2
	mrs	x1, far_el2
	mrs	x2, elr_el2
	mrs	x3, spsr_el2
	mrs	x4, CurrentEL
	mrs	x5, hcr_el2
	bl	gh_el2_unexpected_c
1:	wfi
	b	1b

	.bss
	.p2align 4
	.globl gh_el2_stack
gh_el2_stack:
	.space	16 * 1024
