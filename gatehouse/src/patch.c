// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/patch.c - deliberate deviations from the shipped XNU image.
 *
 * Gatehouse owns exactly one place where the kernel is *changed* on the way in:
 * here.  Every entry is a named, auditable fixup with a comment explaining why
 * it is needed and why it is safe, so that the loader stays honest about the
 * fact that it is not running the kernel byte-for-byte as shipped.
 *
 * Load *completion* is not a deviation and does not belong here: resolving
 * LC_DYLD_CHAINED_FIXUPS (what iBoot/dyld do for every Mach-O) lives in
 * fixups.c, and copying the segments lives in macho.c.  If you want to know
 * how Gatehouse departs from Apple's build, this file is the whole answer.
 */
#include "gh.h"

#define ARM64_NOP 0xd503201fu

static u32 rd32(const u8 *p)
{
	return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static void wr32(u8 *p, u32 v)
{
	p[0] = (u8)(v & 0xff);
	p[1] = (u8)((v >> 8) & 0xff);
	p[2] = (u8)((v >> 16) & 0xff);
	p[3] = (u8)((v >> 24) & 0xff);
}

/* Linear 4-byte-aligned search for a little-endian instruction pattern. */
static u64 find_pattern(const u8 *base, u64 size, const u32 *pat, u32 n)
{
	u64 i;

	if (size < (u64)n * 4) {
		return (u64)-1;
	}
	for (i = 0; i + (u64)n * 4 <= size; i += 4) {
		u32 j;
		for (j = 0; j < n; j++) {
			if (rd32(base + i + j * 4) != pat[j]) {
				break;
			}
		}
		if (j == n) {
			return i;
		}
	}
	return (u64)-1;
}

/*
 * The Apple VM platform hands its guest two pieces of key material over
 * hypercalls at EL2, and the vmapple kernel treats "no answer" as fatal:
 *
 *	0xc1000000	PAC_INIT_KEY_STATE	 (emitted once at the top of common_start)
 *	0xc1000001	default ROP/JOP pids	 (inlined at every site that reads them)
 *
 * EL2 on this machine is PSCI, which answers every function it does not know
 * with NOT_SUPPORTED (-1), so both calls fail and the kernel wedges.  Neither
 * value is a secret the kernel has to agree on with anyone else: the kernel
 * primes them, caches them in its own globals, and then only ever signs and
 * authenticates its own pointers with them, so leaving them at their reset
 * values is self-consistent.  We therefore neutralise exactly the wedge (the
 * 'cbnz x0, .' that spins forever) and leave the hvc in place -- it costs
 * nothing to trap and keeps the call sites recognisable.
 */
static int patch_apple_key_hypercalls(u8 *img, u64 span)
{
	static const u32 sig_pac[] = { 0xd2b82000u, 0xd4000002u, 0xb5000000u };
	u64 off = find_pattern(img, span, sig_pac, 3);
	int applied = 0;

	if (off != (u64)-1) {
		wr32(img + off + 8, ARM64_NOP);
		applied++;
	}

	/*
	 * The 0xc1000001 sites all have the same five-instruction shape; the
	 * temporary register N is the only thing that varies (and the same N
	 * appears in all three of its instructions, which is what pins the
	 * function id to 0xc1000001 rather than one of the nearby ids).
	 *
	 *	movz	wN, #1
	 *	movk	wN, #0xc100, lsl #16
	 *	mov	x0, wN
	 *	hvc	#0
	 *	cbnz	x0, .			; wedge unless the hypervisor answered
	 */
	{
		u64 i;
		u32 sites = 0;

		for (i = 0; i + 20 <= span; i += 4) {
			u32 r0 = rd32(img + i);
			u32 r1 = rd32(img + i + 4);
			u32 r2 = rd32(img + i + 8);
			u32 n;

			if ((r0 & 0xffffffe0u) != 0x52800020u) {	/* movz wN, #1 */
				continue;
			}
			if ((r1 & 0xffffffe0u) != 0x72b82000u) {	/* movk wN, #0xc100, lsl #16 */
				continue;
			}
			n = r0 & 0x1fu;
			if ((r1 & 0x1fu) != n) {
				continue;
			}
			if (r2 != (0xaa0003e0u | (n << 16))) {		/* mov x0, wN */
				continue;
			}
			if (rd32(img + i + 12) != 0xd4000002u) {	/* hvc #0 */
				continue;
			}
			if (rd32(img + i + 16) != 0xb5000000u) {	/* cbnz x0, . */
				continue;
			}
			wr32(img + i + 16, ARM64_NOP);
			sites++;
		}
		gh_loghex("vm platform key hypercalls neutralised: ", sites);
		applied += (int)sites;
	}

	return applied;
}

int gh_patch_kernel(u8 *img, u64 span)
{
	int applied = 0;

	/* Apple VM platform key hypercalls (see above). */
	applied += patch_apple_key_hypercalls(img, span);

	return applied;
}
