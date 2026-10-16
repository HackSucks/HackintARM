// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/fixups.c - chained-fixup resolution ("load completion").
 *
 * The KDK kernel is an ordinary Mach-O, not a kernel collection: it is linked
 * but not relocated, and MH_DYLIB_IN_CACHE is clear.  The pointers in
 * __DATA_CONST, __KLDDATA, __DATA and __BOOTDATA are therefore still in their
 * encoded LC_DYLD_CHAINED_FIXUPS form, and XNU is entitled to treat them as
 * real pointers -- arm_init dereferences one of them a few hundred
 * instructions after entry, and dies on it.
 *
 * Resolving them is a loader duty: iBoot does it on an Apple SoC, dyld does it
 * for every other Mach-O.  Gatehouse does it here, so that what the kernel
 * executes is exactly what Apple built, merely placed in memory.  Deliberate
 * deviations from the shipped image belong in patch.c and only there.
 *
 * Encoding (pointer format DYLD_CHAINED_PTR_ARM64E_OFFSET = 7):
 *
 *   bit 63       auth
 *   bit 62       bind                       (never set by ld64 for a kernel)
 *   bits 61:51   next   offset to the next slot in the chain, in 4-byte
 *                       units; 0 terminates the chain
 *
 *   plain rebase bits 42:0  target, a virtual offset from the image base
 *                bits 50:43 high8, OR'ed into the result's top byte
 *
 *   auth rebase  bits 31:0  target, a virtual offset from the image base
 *                bits 47:32 diversity
 *                bit  48     addrDiv
 *                bits 50:49  key (0 = IA, 1 = IB, 2 = DA, 3 = DB)
 *
 * An auth rebase is what clang emits for a __ptrauth pointer with a static
 * initialiser, so the signature must be produced with the same key and
 * modifier the kernel will later authenticate with.  XNU's own chained-fixup
 * applier runs in arm_init() (0xfffffe0007faa820) and defines the convention:
 *
 *     if (!addrDiv)                mod = diversity
 *     else if (diversity == 0)     mod = loc                 (full 64-bit VA)
 *     else                         mod = (loc & 0x0000ffffffffffff)
 *                                        | ((u64)diversity << 48)
 *
 * where loc is the *virtual* address of the slot itself, not the pointer's
 * value.  The three cases match the three call-site code shapes the toolchain
 * emits (adrp+add; adrp+add; adrp+add+movk #diversity).  Note dyld's
 * _fixupPageAuth64/_signPointer always blends, which is equivalent for user
 * VAs because those have a zero top half; kernel VAs are 0xfffffe.. and need
 * the raw address when diversity is zero.
 */
#include "gh.h"

#define LC_SEGMENT_64          0x00000019u
#define LC_DYLD_CHAINED_FIXUPS 0x80000034u

#define GH_PTR_ARM64E_OFFSET   7u
#define GH_CHAIN_NONE          0xffffu  /* page carries no fixups        */
#define GH_CHAIN_MULTI         0x8000u  /* page_start indexes an overflow list */

/* ---------------------------------------------------------------- */

static u16 rd16(const u8 *p)
{
	return (u16)((u32)p[0] | ((u32)p[1] << 8));
}

static u32 rd32(const u8 *p)
{
	return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) |
	    ((u32)p[3] << 24);
}

static u64 rd64(const u8 *p)
{
	u64 v;
	__builtin_memcpy(&v, p, sizeof(v));
	return v;
}

static void wr64(u8 *p, u64 v)
{
	__builtin_memcpy(p, &v, sizeof(v));
}

/* ---------------------------------------------------------------- */
/* Pointer authentication                                           */

/*
 * pac* is UNDEFINED unless EL1 has been granted the feature, and PAuth is
 * off by default in the firmware's SCTLR_EL1.  Probe ID_AA64ISAR1_EL1 (API is
 * bits 7:4, APA is bits 11:8; zero means "not implemented") and then set the
 * four enable bits before signing anything.
 */
static int gh_pauth_enable(void)
{
	u64 isar1, sctlr;

	__asm__ volatile("mrs %0, id_aa64isar1_el1" : "=r"(isar1));
	/*
	 * APA (bits 7:4) is address authentication, API (bits 11:8) is generic
	 * authentication.  A CPU that implements either one decodes the PAC
	 * instructions -- and that is precisely the test QEMU itself uses
	 * (isar_feature_aa64_pauth), which matters here because QEMU's -cpu max
	 * advertises API=5 / APA=0.  Requiring both would refuse a CPU that
	 * has the instructions.
	 */
	if (((isar1 >> 8) & 0xf) == 0 && ((isar1 >> 4) & 0xf) == 0) {
		return 0;
	}
	__asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
	sctlr |= (1ULL << 31) | (1ULL << 30) |    /* EnIA, EnIB */
	    (1ULL << 27) | (1ULL << 26);          /* EnDA, EnDB */
	__asm__ volatile("msr sctlr_el1, %0" : : "r"(sctlr));
	__asm__ volatile("isb");
	return 1;
}

static u64 gh_pac_sign(u64 ptr, u64 modifier, u32 key)
{
	switch (key & 3) {
	case 0:
		__asm__ volatile("pacia %0, %1" : "+r"(ptr) : "r"(modifier));
		break;
	case 1:
		__asm__ volatile("pacib %0, %1" : "+r"(ptr) : "r"(modifier));
		break;
	case 2:
		__asm__ volatile("pacda %0, %1" : "+r"(ptr) : "r"(modifier));
		break;
	default:
		__asm__ volatile("pacdb %0, %1" : "+r"(ptr) : "r"(modifier));
		break;
	}
	return ptr;
}

static volatile u64 gh_blraa_ran;

static void gh_blraa_target(void)
{
	gh_blraa_ran = 1;
}

/*
 * Sign a function pointer the way the fixup pass signs the kernel's, then
 * branch to it with the same instruction arm_init uses (blraa, key IA).  If
 * this does not set the flag, our signatures and/or the CPU's register-form
 * PAC branches are the problem, and no amount of kernel debugging will help.
 */
static int gh_blraa_works(void)
{
	u64 s = gh_pac_sign((u64)&gh_blraa_target, 0x2abe, 0);

	gh_blraa_ran = 0;
	__asm__ volatile("mov x8, %0\n\t"
	    "mov x17, %1\n\t"
	    "blraa x8, x17" ::
	    "r"(s), "r"(0x2abeULL) : "x8", "x17", "x30", "memory");
	return gh_blraa_ran == 1;
}

/* Sign a canary and authenticate it again: the cheapest way to know that the
 * signatures we are about to write are the ones the kernel will accept. */
static int gh_pac_works(u64 link_base)
{
	u64 v = link_base + 0x1234, m = 0x5a5a5a5a;
	u64 a = gh_pac_sign(v, m, 0);

	__asm__ volatile("autia %0, %1" : "+r"(a) : "r"(m));
	return a == v;
}

/* ---------------------------------------------------------------- */
/*
 * The VA configuration is part of the signature
 * --------------------------------------------
 * A PAC is only valid inside the translation regime configuration that
 * produced it.  The PAC field is the top of the pointer, and *how much* of
 * the pointer is signature depends on the VA size of the regime the pointer
 * belongs to:
 *
 *     pac_field = bits[(64 - tsz) .. 63]        tsz = T1SZ for kernel VAs
 *
 * UEFI (AAVMF) leaves TCR_EL1.T1SZ at 16: a 48-bit VA, so a 16-bit PAC field
 * in bits 63:48.  XNU's start.s programs its own TCR before running any C
 * code --
 *
 *     TCR_EL1_BOOT = 0x0008_0022_6511_a511      T0SZ = T1SZ = 17, TBI1 = 0
 *
 * (common_start, 0xfffffe00073ec28c; the AS bit 36 is OR'ed in when the CPU
 * reports 16-bit ASIDs) -- and nothing rewrites it afterwards (_set_tcr is
 * unused).  So arm_init's
 *
 *     arm_init+0x2c8:  blraa x8, x17
 *
 * authenticates against a 17-bit field in bits 63:47.  Signing with the
 * firmware's 16-bit field leaves bit 47 holding an address bit where the
 * kernel expects a PAC bit, which is exactly the observed
 *
 *     Taking exception 1 [Undefined Instruction], ESR 0x1c/0x72000000
 *     (EC 0x1c = syn_pacfail), ELR 0xfffffe0007faaa18
 *
 * Sign with the T1 fields XNU will verify with.  Only TTBR1 is touched:
 * Gatehouse itself runs through TTBR0 (low VAs, T0SZ/TG0 untouched), so its
 * own execution is unaffected, and the firmware's configuration is restored
 * before returning.
 */
#define GH_TCR_T1SZ  17u	/* XNU TCR_EL1_BOOT: 47-bit kernel VA */
#define GH_TCR_TBI1  0u		/* ... and no top-byte ignore there */

static u64 gh_tcr_uefi;

static void gh_sign_config_enter(void)
{
	u64 tcr;

	__asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
	gh_tcr_uefi = tcr;

	tcr &= ~((0x3fULL << 16) | (1ULL << 38));	/* T1SZ, TBI1 */
	tcr |= ((u64)GH_TCR_T1SZ << 16) | ((u64)GH_TCR_TBI1 << 38);
	__asm__ volatile("msr tcr_el1, %0\n\tisb" : : "r"(tcr));

	gh_loghex("tcr_el1 (uefi)  : ", gh_tcr_uefi);
	gh_loghex("  T1SZ/48-bit   : ", (gh_tcr_uefi >> 16) & 0x3f);
	gh_loghex("tcr_el1 (sign)  : ", tcr);
	gh_loghex("  T1SZ/47-bit   : ", (tcr >> 16) & 0x3f);
}

static void gh_sign_config_leave(void)
{
	__asm__ volatile("msr tcr_el1, %0\n\tisb" : : "r"(gh_tcr_uefi));
}

/* ---------------------------------------------------------------- */

static int find_chained(const gh_macho *m, const u8 **blob, u64 *blob_len)
{
	const u8 *f = m->file;
	u32 ncmds, i, off = 32;

	if (!f || m->filesize < 32) {
		return -1;
	}
	ncmds = rd32(f + 16);
	for (i = 0; i < ncmds; i++) {
		u32 cmd, size;

		if ((u64)off + 8 > m->filesize) {
			return -1;
		}
		cmd = rd32(f + off);
		size = rd32(f + off + 4);
		if (size < 8) {
			return -1;
		}
		if (cmd == LC_DYLD_CHAINED_FIXUPS) {
			u32 doff = rd32(f + off + 8);
			u32 dlen = rd32(f + off + 12);

			if ((u64)doff + dlen > m->filesize) {
				return -1;
			}
			*blob = f + doff;
			*blob_len = dlen;
			return 0;
		}
		off += size;
	}
	return -1;
}

/* Nice-to-have: attribute a segment_offset back to a segment name. */
static const char *seg_for_offset(const gh_macho *m, u64 off)
{
	u32 i;

	for (i = 0; i < m->nsegs; i++) {
		if (m->segs[i].vmaddr >= m->link_base &&
		    m->segs[i].vmaddr - m->link_base == off) {
			return m->segs[i].segname;
		}
	}
	return "?";
}

int gh_apply_fixups(const gh_macho *m, u8 *img)
{
	const u8 *blob;
	u64 blob_len, link_base = m->link_base;
	u32 ver, starts_off, imports_count, nseg, i;
	u64 applied = 0, auth_applied = 0;
	int pauth, warned_multi = 0;

	if (find_chained(m, &blob, &blob_len) != 0) {
		gh_log("chained fixups  : none (kernel collection?)\n");
		return 0;
	}

	ver = rd32(blob + 0);
	starts_off = rd32(blob + 4);
	imports_count = rd32(blob + 16);
	if (ver != 0) {
		gh_loghex("chained fixups  : unsupported version ", ver);
		return 0;
	}
	if ((u64)starts_off + 4 > blob_len) {
		gh_log("chained fixups  : truncated starts_in_image\n");
		return 0;
	}
	if (imports_count) {
		gh_loghex("chained fixups  : binds present, unsupported: ",
		    imports_count);
	}

	/*
	 * Everything from here to the end of the walk signs with pacia, so it
	 * must run under the VA configuration XNU will authenticate with.
	 */
	gh_sign_config_enter();

	pauth = 0;
	{
		u64 midr, pfr0, isar1, sctlr0;

		__asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
		__asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));
		__asm__ volatile("mrs %0, id_aa64isar1_el1" : "=r"(isar1));
		__asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr0));
		gh_loghex("cpu midr        : ", midr);
		gh_loghex("id_aa64pfr0     : ", pfr0);
		gh_loghex("id_aa64isar1    : ", isar1);
		gh_loghex("  (API:APA)     : ",
		    (u64)((((isar1 >> 8) & 0xf) << 4) | ((isar1 >> 4) & 0xf)));
		gh_loghex("sctlr_el1       : ", sctlr0);

		pauth = gh_pauth_enable();
		gh_loghex("pauth support   : ", (u64)(pauth ? 1 : 0));
		if (pauth && gh_pac_works(link_base)) {
			gh_log("pauth selftest  : sign/auth roundtrip ok\n");
		} else if (pauth) {
			gh_log("pauth selftest  : FAILED (signatures unreliable)\n");
		} else {
			gh_log("pauth           : not implemented; auth fixups left unsigned\n");
		}
		/*
		 * Diagnose the pair (signature, blraa) end to end.  Log the live
		 * instruction/data key halves so the values the fixup pass signed
		 * with can be compared against the values in force when the kernel
		 * authenticates.
		 */
		if (pauth) {
			u64 k0, k0h, k2, k2h;

			__asm__ volatile("mrs %0, APIAKeyLo_EL1" : "=r"(k0));
			__asm__ volatile("mrs %0, APIAKeyHi_EL1" : "=r"(k0h));
			__asm__ volatile("mrs %0, APDAKeyLo_EL1" : "=r"(k2));
			__asm__ volatile("mrs %0, APDAKeyHi_EL1" : "=r"(k2h));
			gh_loghex("APIAKey lo      : ", k0);
			gh_loghex("APIAKey hi      : ", k0h);
			gh_loghex("APDAKey lo      : ", k2);
			gh_loghex("APDAKey hi      : ", k2h);
			gh_log("pauth blraa test: running\n");
			if (gh_blraa_works()) {
				gh_log("pauth blraa test: ok\n");
			} else {
				gh_log("pauth blraa test: no effect\n");
			}
		}
	}

	nseg = rd32(blob + starts_off);
	for (i = 0; i < nseg; i++) {
		const u8 *p;
		u64 seg_off, seg_applied = 0;
		u32 size, page_size, fmt, page_count, pg;
		const u8 *starts;

		if ((u64)starts_off + 4 + 4 * i + 4 > blob_len) {
			break;
		}
		{
			u32 so = rd32(blob + starts_off + 4 + 4 * i);

			if (so == 0) {
				continue;
			}
			if ((u64)starts_off + so + 22 > blob_len) {
				gh_log("chained fixups  : segment info past blob\n");
				break;
			}
			p = blob + starts_off + so;
		}
		size = rd32(p + 0);
		page_size = rd16(p + 4);
		fmt = rd16(p + 6);
		seg_off = rd64(p + 8);
		page_count = rd16(p + 20);
		starts = p + 22;
		if ((u64)size < 22 + 2 * (u64)page_count) {
			gh_log("chained fixups  : bad page_start table\n");
			break;
		}
		if (fmt != GH_PTR_ARM64E_OFFSET) {
			gh_loghex("chained fixups  : unknown pointer format ", fmt);
			continue;
		}

		for (pg = 0; pg < page_count; pg++) {
			u32 ps = rd16(starts + 2 * pg);
			u64 voff;

			if (ps == GH_CHAIN_NONE) {
				continue;
			}
			if (ps & GH_CHAIN_MULTI) {
				if (!warned_multi) {
					gh_log("chained fixups  : multi-start page skipped\n");
					warned_multi = 1;
				}
				continue;
			}
			voff = seg_off + (u64)pg * page_size + ps;
			for (;;) {
				u64 val = rd64(img + voff);
				u64 next = (val >> 51) & 0x7ff;
				u64 ptr;

				if (val & (1ULL << 62)) {
					gh_log("chained fixups  : bind chain, unsupported\n");
					break;
				}
				if (val & (1ULL << 63)) {
					u64 target = val & 0xffffffffULL;
					u64 diversity = (val >> 32) & 0xffff;
					u32 key = (u32)((val >> 49) & 3);
					u64 loc = link_base + voff;
					u64 mod;

					ptr = link_base + target;
					/*
					 * The discriminator is exactly what the
					 * call site builds in its modifier register.
					 * XNU applies its own chained fixups in
					 * arm_init() (0xfffffe0007faa820), and that
					 * code is authoritative:
					 *
					 *     mov  x16, x12          ; x16 = &slot
					 *     bfi  x16, x15, #48, #16 ; blend diversity
					 *     cmp  x15, #0           ; diversity == 0?
					 *     csel x16, x12, x16, eq ;   -> raw &slot
					 *     tst  x13, #1<<48       ; addrDiv?
					 *     csel x16, x15, x16, eq ; addrDiv==0 -> diversity
					 *     pacia/pacib/pacda/pacdb x17, x16
					 *
					 * i.e. addrDiv==0            -> mod = diversity
					 *      addrDiv==1, diversity==0 -> mod = &slot (full VA)
					 *      addrDiv==1, diversity!=0 -> mod = (&slot & 0xffffffffffff)
					 *                                       | (diversity << 48)
					 *
					 * The toolchain emits the same three forms at
					 * the call sites: a bare adrp+add for the
					 * address-discriminated case, adrp+add+movk
					 * #diversity for the blended case.
					 */
					if (!((val >> 48) & 1)) {
						mod = diversity;
					} else if (diversity == 0) {
						mod = loc;
					} else {
						mod = (loc & 0x0000ffffffffffffULL) |
						    ((u64)diversity << 48);
					}
					if (pauth) {
						ptr = gh_pac_sign(ptr, mod, key);
					}
					auth_applied++;
				} else {
					u64 target = val & 0x7ffffffffffULL;
					u64 high8 = (val >> 43) & 0xff;

					ptr = (link_base + target) |
					    (high8 << 56);
				}
				wr64(img + voff, ptr);
				applied++;
				seg_applied++;
				if (next == 0) {
					break;
				}
				voff += next * 4;
			}
		}
		gh_uart_puts("  fixups ");
		gh_uart_puts(seg_for_offset(m, seg_off));
		gh_uart_puts(": ");
		gh_uart_putdec(seg_applied);
		gh_uart_putc('\n');
	}

	gh_uart_puts("chained fixups  : ");
	gh_uart_putdec(applied);
	gh_uart_puts(" applied (");
	gh_uart_putdec(auth_applied);
	gh_uart_puts(" signed)\n");
	/*
	 * TEMPORARY WITNESS: the first entry of the init-routine table that
	 * arm_init branches to with blraa (vmoff 0x1200610).  Compare this with
	 * the word at the physical address when the kernel faults.
	 */
	{
		const u64 *w = (const u64 *)(img + 0x1200610);

		gh_loghex("witness slot    : ", w[0]);
		gh_loghex("  want signed   : ",
		    gh_pac_sign(link_base + 0x00451f64, 0x2abe, 0));
	}
	gh_sign_config_leave();
	return (int)applied;
}
