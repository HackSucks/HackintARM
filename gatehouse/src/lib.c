// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/lib.c - freestanding string/memory helpers + logging.
 */
#include "gh.h"
#include "version.h"

/*
 * Build the build number from __DATE__, which C guarantees is "Mmm DD YYYY"
 * (the day is space-padded, not zero-padded, for single digits).  We want
 * DDMMYY followed by the stage suffix.
 */
const char *gh_version_string(char *buf)
{
	static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
	const char *d = __DATE__;
	const char *p = months;
	int mon = 1, day, year, i = 0;

	for (; p < months + 36; p += 3) {
		if (p[0] == d[0] && p[1] == d[1] && p[2] == d[2]) {
			mon = (int)((p - months) / 3) + 1;
			break;
		}
	}
	day = (d[4] == ' ' ? 0 : d[4] - '0') * 10 + (d[5] - '0');
	year = (d[7] - '0') * 1000 + (d[8] - '0') * 100 +
	    (d[9] - '0') * 10 + (d[10] - '0');

	buf[i++] = (char)('0' + day / 10);
	buf[i++] = (char)('0' + day % 10);
	buf[i++] = (char)('0' + mon / 10);
	buf[i++] = (char)('0' + mon % 10);
	buf[i++] = (char)('0' + (year / 10) % 10);
	buf[i++] = (char)('0' + year % 10);

	for (p = GH_VERSION_STAGE; *p; p++) {
		buf[i++] = *p;
	}
	buf[i] = 0;
	return buf;
}

void *gh_memset(void *d, int c, u64 n)
{
	u8 *p = (u8 *)d;
	while (n--) {
		*p++ = (u8)c;
	}
	return d;
}

void *gh_memcpy(void *d, const void *s, u64 n)
{
	u8 *dp = (u8 *)d;
	const u8 *sp = (const u8 *)s;
	while (n--) {
		*dp++ = *sp++;
	}
	return d;
}

int gh_memcmp(const void *a, const void *b, u64 n)
{
	const u8 *x = (const u8 *)a, *y = (const u8 *)b;
	while (n--) {
		if (*x != *y) {
			return (int)*x - (int)*y;
		}
		x++;
		y++;
	}
	return 0;
}

u64 gh_strlen(const char *s)
{
	u64 n = 0;
	while (s[n]) {
		n++;
	}
	return n;
}

void gh_log(const char *s)
{
	gh_uart_puts(s);
}

void gh_loghex(const char *tag, u64 v)
{
	gh_uart_puts(tag);
	gh_uart_puthex(v);
	gh_uart_putc('\n');
}

/* The exception level this code is running at (0-3).  Gatehouse runs at the
 * EL the firmware hands it: EL1 without the virtualization extensions, EL2
 * with them (QEMU `virt,virtualization=on`, and on hardware with EL2).  The
 * distinction decides whether the final handoff has to install Trestle's
 * EL2 state before eret-ing to XNU at EL1. */
u64 gh_current_el(void)
{
	u64 v;
	__asm__ volatile("mrs %0, CurrentEL" : "=r"(v));
	return (v >> 2) & 3;
}

__attribute__((used))
void gh_el2_unexpected_c(u64 esr, u64 far, u64 elr, u64 spsr, u64 cel, u64 hcr)
{
	gh_uart_puts("\nEL2 unexpected exception\n");
	gh_loghex("esr_el2         : ", esr);
	gh_loghex("far_el2         : ", far);
	gh_loghex("elr_el2         : ", elr);
	gh_loghex("spsr_el2        : ", spsr);
	gh_loghex("CurrentEL       : ", cel);
	gh_loghex("hcr_el2         : ", hcr);
	for (;;) {
		__asm__ volatile("wfi");
	}
}

/*
 * The first service behind Trestle's EL2 trap layer: HVC/SMC from XNU.
 *
 * With EL2 present, every HVC and SMC executed at EL1 traps to Trestle.  Two
 * callers exist on this platform:
 *
 *   - PSCI (0x8400_00xx / 0xc400_00xx), which QEMU used to answer itself;
 *   - Apple's AVP platform calls (0xc100_00xx).  Gatehouse has already
 *     neutralised the "branch to self unless x0 == 0" wedge after each site,
 *     so NOT_SUPPORTED is the same answer QEMU gave and is safe here.
 *
 * The PSCI subset is the one Trestle's power manager will own once the
 * platform library is linked into the boot image; keeping it here for now
 * means the EL1 handoff can be validated without that larger change.
 *
 * Note: for HVC/SMC the architectural preferred return address is already the
 * instruction *after* the trap, so ELR_EL2 is returned unchanged.
 */
#define ESR_EC_HVC64	0x16u
#define ESR_EC_SMC64	0x17u
#define ESR_EC_DABT_LOW	0x24u

#define GH_PSCI_ID_MASK	0xbfffffffu

static i64 gh_psci(u32 function, u64 arg0)
{
	u32 fn = function & GH_PSCI_ID_MASK;

	switch (fn) {
	case 0x84000000u:			/* PSCI_VERSION */
		return ((i64)1 << 16) | 1;	/* 1.1 */
	case 0x8400000au:			/* PSCI_FEATURES */
		switch ((u32)arg0 & GH_PSCI_ID_MASK) {
		case 0x84000000u:		/* VERSION */
		case 0x8400000au:		/* FEATURES */
		case 0x84000004u:		/* AFFINITY_INFO */
		case 0x84000001u:		/* CPU_SUSPEND */
		case 0x84000002u:		/* CPU_OFF */
		case 0x84000003u:		/* CPU_ON */
		case 0x84000008u:		/* SYSTEM_OFF */
		case 0x84000009u:		/* SYSTEM_RESET */
			return 0;
		default:
			return -1;
		}
	case 0x84000004u:			/* AFFINITY_INFO */
		return arg0 == 0 ? 0 : -2;	/* ON, or INVALID_PARAMS */
	case 0x84000003u:			/* CPU_ON */
		return arg0 == 0 ? -4 : -2;	/* ALREADY_ON, or INVALID */
	case 0x84000002u:			/* CPU_OFF */
	case 0x84000001u:			/* CPU_SUSPEND */
	case 0x84000005u:			/* MIGRATE */
	case 0x84000008u:			/* SYSTEM_OFF */
	case 0x84000009u:			/* SYSTEM_RESET */
		return 0;
	default:
		return -1;			/* NOT_SUPPORTED */
	}
}

__attribute__((used))
u64 gh_el2_trap_c(u64 esr, u64 far, u64 hpfar, u64 elr, u64 *regs)
{
	u32 ec = (u32)(esr >> 26) & 0x3fu;

	if (ec == ESR_EC_HVC64 || ec == ESR_EC_SMC64) {
		u64 fn = regs[0];
		i64 ret;

		if ((fn >> 24) == 0x84u || (fn >> 24) == 0xc4u)
			ret = gh_psci((u32)fn, regs[1]);
		else
			ret = -1;		/* Apple 0xc100_00xx */

		regs[0] = (u64)ret;
		return elr;
	}

	if (ec == ESR_EC_DABT_LOW) {
		u32 iss = (u32)(esr & 0x1ffffffu);
		/*
		 * HPFAR_EL2.FIPA holds the faulting IPA's page in bits
		 * [47:4] (bits [47:12] of the IPA), not at the IPA's own
		 * bit positions, and FAR_EL2 supplies the 4 KiB offset.
		 * With the 40-bit IPA this image uses, FIPA[35:4] is
		 * IPA[39:12].
		 */
		u64 ipa = ((hpfar & 0xfffffffff0ull) << 8) | (far & 0xfffull);
		u32 sas = (iss >> 22) & 3u;
		u32 srt = (iss >> 16) & 0x1fu;
		u64 size = 1ull << sas;
		u64 mask = (size == 8) ? ~0ull : ((1ull << (size * 8)) - 1);
		int is_write = (int)((iss >> 6) & 1u);

		/*
		 * Only a stage-2 fault with a valid syndrome is emulated, and
		 * only for Lantern's windows.  Anything else is a bug in the
		 * map, not a device access: report it rather than returning
		 * a plausible-looking zero.
		 */
		if ((iss & (1u << 24)) &&
		    ipa >= GH_LANTERN_GFX_BASE &&
		    ipa < GH_LANTERN_IOSFC_BASE + GH_LANTERN_WINDOW_SIZE) {
			if (is_write) {
				u64 value = (srt == 31) ? 0 : regs[srt];

				gh_lantern_mmio_write(ipa, (u32)size,
						      value & mask, elr);
			} else {
				u64 value = gh_lantern_mmio_read(ipa,
								 (u32)size, elr) &
					     mask;

				if (!(iss & (1u << 15)))	/* SF */
					value &= 0xffffffffull;
				if (iss & (1u << 21)) {		/* SSE */
					u32 sh = 64 - (u32)(size * 8);

					value = (u64)((i64)(value << sh) >> sh);
				}
				if (srt != 31)
					regs[srt] = value;
			}
			return elr + 4;
		}

		gh_uart_puts("\nEL2 data abort\n");
		gh_loghex("esr_el2         : ", esr);
		gh_loghex("far_el2         : ", far);
		gh_loghex("hpfar_el2       : ", hpfar);
		gh_loghex("ipa             : ", ipa);
		gh_loghex("elr_el2         : ", elr);
		for (;;) {
			__asm__ volatile("wfi");
		}
	}

	gh_uart_puts("\nEL2 unhandled synchronous trap\n");
	gh_loghex("esr_el2         : ", esr);
	gh_loghex("elr_el2         : ", elr);
	gh_loghex("x0              : ", regs[0]);
	for (;;) {
		__asm__ volatile("wfi");
	}
}

/* clang for the aarch64-windows target may emit this for big frames. */
void __chkstk(void) { }
void _chkstk(void) { }

/*
 * Force lld to emit a .reloc section.  Our code addresses data PC-relatively
 * (ADRP/ADD), so without an absolute reference lld produces a PE with
 * DYNAMIC_BASE set and no relocation directory -- which the EDK2 PE loader
 * refuses to load at a non-preferred base.
 */
extern void gh_jump_to_kernel(u64, u64, u64, u64, u64);
__attribute__((used)) const unsigned long long gh_reloc_anchor =
    (unsigned long long)&gh_jump_to_kernel;
