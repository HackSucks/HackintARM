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

/* arm64e function furniture and a couple of one-instruction bodies. */
#define ARM64_BTI_C	0xd503245fu	/* "bti c": only a direct branch may land */
#define ARM64_PACIBSP	0xd503237fu	/* sign LR with the B key and SP */
#define ARM64_RETAB	0xd65f0fffu	/* authenticate LR (B key, SP) and return */
#define ARM64_MOV_W0_0	0x52800000u	/* "mov w0, #0" */
#define PAGE_MASK	(~(u64)0xfff)	/* 4 KiB page base (~int would truncate) */

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
 * Apple VM platform hypercalls on a machine that does not answer them.
 *
 * The vmapple kernel calls up to EL2 with hvc #0 to ask its host for things
 * only a virtualisation host can give it.  The ids live in Apple's own
 * 0xc100____ space:
 *
 *	0xc1000000	PAC_INIT_KEY_STATE	(once, at the top of common_start:
 *						the host picks the kernel's
 *						pointer-signing keys)
 *	0xc1000001	default ROP/JOP pids	(inlined at every site that reads
 *						them)
 *	0xc1000003/4	publish a vcpu's state to the host
 *	0xc1000005	guest feature query
 *
 * and every one of them treats "no answer" as fatal by branching to itself:
 *
 *	hvc	#0
 *	cbnz	x0, .			; spin forever unless the host accepted
 *
 * EL2 on this machine is PSCI, which answers every function id it does not
 * know with NOT_SUPPORTED (-1), so all 19 sites wedge -- common_start never
 * even reaches the point where the kernel starts.  None of the values carried
 * here has to be agreed with anyone: the kernel primes its own keys, caches
 * them in its own globals and then only ever signs and authenticates its own
 * pointers with them, so their reset values are self-consistent; the
 * context/feature calls are "tell the host" calls whose only consequence for
 * the guest is a cached copy of what it said.
 *
 * We therefore neutralise exactly the wedge -- the branch to self after the
 * trap -- and leave the hvc in place: the trap costs nothing, the call sites
 * stay recognisable, and a machine that does have an AVP host still reaches
 * it.
 *
 * The rule is deliberately narrow: an hvc whose x0 is built from a 0xc100
 * halfword within the four instructions before it, followed by a branch to
 * itself.  PSCI's CPU_OFF and CPU_DEFAULT_SUSPEND (0x84000002/0xc400000e)
 * also end in a parking loop, but there the CPU is meant never to come back,
 * which is correct behaviour and must not be touched.
 */
#define ARM64_HVC0 0xd4000002u

/* "movz|movk wN|xN, #imm16, lsl #shift"? */
static int mov_imm(u32 insn, u32 *imm16, u32 *shift)
{
	if ((insn & 0xff800000u) != 0x52800000u &&	/* movz w */
	    (insn & 0xff800000u) != 0x72800000u &&	/* movk w */
	    (insn & 0xff800000u) != 0xd2800000u &&	/* movz x */
	    (insn & 0xff800000u) != 0xf2800000u) {	/* movk x */
		return 0;
	}
	*imm16 = (insn >> 5) & 0xffffu;
	*shift = ((insn >> 21) & 3u) * 16u;
	return 1;
}

/* Does one of the four instructions before this hvc build an 0xc100 id? */
static int avp_call_id(const u8 *img, u64 at)
{
	u32 k;

	for (k = 1; k <= 4; k++) {
		u32 imm16, shift;

		if (mov_imm(rd32(img + at - 4 * k), &imm16, &shift) &&
		    imm16 == 0xc100u) {
			return 1;
		}
	}
	return 0;
}

/*
 * A branch to itself: "b ." (B with a zero displacement) or "cbz/cbnz
 * wN|xN, ." (conditional, zero 19-bit displacement).  Nothing can leave such
 * a loop, which is what makes these sites wedges rather than retries.
 */
static int is_self_branch(u32 insn)
{
	if ((insn & 0xfc000000u) == 0x14000000u) {	/* B */
		return (insn & 0x03ffffffu) == 0u;
	}
	if ((insn & 0x7f000000u) == 0x34000000u ||	/* CBZ  w/x */
	    (insn & 0x7f000000u) == 0x35000000u) {	/* CBNZ w/x */
		return ((insn >> 5) & 0x7ffffu) == 0u;
	}
	return 0;
}

static int patch_apple_hypercalls(u8 *img, u64 span)
{
	u64 i;
	u32 sites = 0;

	for (i = 16; i + 8 <= span; i += 4) {
		if (rd32(img + i) != ARM64_HVC0) {
			continue;
		}
		if (!avp_call_id(img, i)) {
			continue;
		}
		if (!is_self_branch(rd32(img + i + 4))) {
			continue;
		}
		wr32(img + i + 4, ARM64_NOP);
		sites++;
	}

	gh_loghex("vm platform hypercall wedges neutralised: ", sites);

	return (int)sites;
}

/*
 * IOPCIDevice::extendedFindPCICapability() capability-search fast path.
 *
 * macOS 27 answers PCI capability lookups for a device out of a per-device
 * capability dictionary that IOPCIBridge::constructCapabilitiesDict() builds.
 * The dictionary is keyed by capability *symbol*, and every capability a
 * virtio-pci device exposes shares one symbol -- all five carry capability ID
 * 0x09 (common / notify / isr / device / pci-cfg) -- so the dictionary collapses
 * to a single entry and the fast path hands back the same capability whatever
 * offset it is given.  AppleVirtIOPCITransport::start() walks a device's vendor
 * capabilities with extendedFindPCICapability(9, &offset) until the call
 * reports none left, so the walk never terminates: the transport never
 * registers, no IOMedia appears and there is no root device.
 *
 * This is not specific to virtio, nor to any machine -- any device that exposes
 * more than one capability with the same ID trips it -- so the deviation lives
 * here, in the loader, and every target gets it.
 *
 * The site is three instructions:
 *
 *	ldr	x8, [x21, #160]		; IOPCIDevice::reserved
 *	ldr	x9, [x8, #472]		; reserved->capability dictionary (may be NULL)
 *	cbz	x9, <search>		; no dictionary: take the reference search
 *
 * Replacing the conditional branch with an unconditional one sends every
 * lookup through the reference config-space search -- the path Apple itself
 * takes whenever the dictionary is absent -- which walks the PCI capability
 * list in config space, iterates correctly and terminates.
 */
static int patch_apple_pci_capability_search(u8 *img, u64 span)
{
	static const u32 site[] = { 0xf94052a8u, 0xf940ed09u };
	u64 off = find_pattern(img, span, site, 2);
	u32 cbz, imm;

	if (off == (u64)-1) {
		return 0;
	}
	/* The next instruction must be "cbz x9, <search>". */
	cbz = rd32(img + off + 8);
	if ((cbz & 0xff00001fu) != 0xb4000009u) {
		return 0;
	}
	/*
	 * cbz reaches +/-1 MiB with a 19-bit immediate and b reaches +/-128 MiB
	 * with a 26-bit one, both scaled by 4 and measured from the same
	 * address, so the branch displacement carries over unchanged.
	 */
	imm = (cbz >> 5) & 0x7ffffu;
	if (imm & 0x40000u) {
		imm |= 0xfff80000u;			/* sign-extend 19 -> 32 */
	}
	wr32(img + off + 8, 0x14000000u | (imm & 0x03ffffffu));	/* b <search> */
	gh_loghex("PCI capability search on the reference path: ", 1);

	return 1;
}

/*
 * Root-volume authentication when the root was not attested by the host.
 *
 * macOS 27 on Apple Virtual platforms treats the root filesystem as an
 * *authenticated* volume.  iBoot forwards the sealed root hash to the kernel
 * in the device tree (system-volume-auth-blob, root-snapshot-name) and
 * bsd_init() insists on it:
 *
 *	IOSecureBSDRoot(rootdevice);				bsd_init.c:916
 *	...
 *	require_rootauth = !imageboot_desired();
 *	if (require_rootauth) {
 *		autherr = VNOP_IOCTL(rootvnode, FSIOC_KERNEL_ROOTAUTH,
 *		    NULL, 0, vfs_context_kernel());
 *		if (autherr) panic("rootvp not authenticated after mounting");
 *	}
 *
 * Both halves of that contract are missing here for the same reason -- the
 * root did not come from Apple's boot chain -- so both deviations live here
 * and every target gets them.
 *
 *   - IOSecureBSDRoot() asks the platform expert to vouch for the root with
 *     callPlatformFunction("SecureRootName", ...).  That is a *host* service:
 *     on Apple's own hypervisor the host attests the root volume it handed
 *     the guest.  Nothing on the guest side can answer it, the dispatch never
 *     returns, and the boot stops in bsd_init() without printing anything.
 *
 *   - APFS answers FSIOC_KERNEL_ROOTAUTH out of is_root_hash_
 *     authentication_required(), which is true for any release-build System
 *     volume ("Root Volume, root hash authentication is required").  With no
 *     iBoot-forwarded root hash and no ARV snapshot on the medium, nothing
 *     could ever satisfy it: the volume mounts and the kernel panics.
 *
 * So: the single "bl <IOSecureBSDRoot>" in bsd_init() becomes a nop, and
 * is_root_hash_authentication_required() is made to return false -- the same
 * statement the kernel logs ("root hash authentication is required"), negated,
 * because without host attestation there is no root hash to check.  The
 * consequence to be honest about: a kernel patched this way cannot detect a
 * tampered root volume.
 *
 * Neither edit hardcodes an address.  Both functions are found by a C string
 * they build ("SecureRootName", "is_root_hash_authentication_required"), then
 * the adrp+add pair that materialises it, then the enclosing function entry,
 * and the locators verify the shape of everything they touch.
 */

/*
 * A kernel collection is loaded as a flat 1:1 image of its VA window, so a
 * file offset and the address the code will run at differ by one constant
 * (segment vmaddr - fileoff).  Gatehouse never relies on that, but the
 * locators below must decode pc-relative operands, which needs a real
 * address.  Return the constant only if every segment agrees on it, so an
 * image with a different layout is left alone rather than mis-patched.
 */
static u64 kc_link_delta(const gh_macho *m)
{
	u64 delta = (u64)-1;
	u32 i;

	for (i = 0; i < m->nsegs; i++) {
		const gh_segment *s = &m->segs[i];
		u64 d;

		if (s->filesize == 0) {
			continue;			/* __bss-like */
		}
		d = s->vmaddr - s->fileoff;
		if (delta == (u64)-1) {
			delta = d;
		} else if (delta != d) {
			return (u64)-1;
		}
	}
	return delta;
}

/* Offset of a NUL-terminated string in the image, or (u64)-1. */
static u64 find_cstring(const u8 *img, u64 span, const char *s)
{
	u64 n = gh_strlen(s);
	u64 i;

	for (i = 0; i + n < span; i++) {
		if (img[i] != (u8)s[0]) {
			continue;
		}
		if (gh_memcmp(img + i, s, n) == 0 && img[i + n] == 0) {
			return i;
		}
	}
	return (u64)-1;
}

/*
 * Find the "adrp xN, <page>; add xN, xN, #<off>" pair that materialises a
 * given address.  Apple's compiler emits the two back to back, which is what
 * makes a string reference a usable function locator.
 */
static u64 find_adrp_add(const u8 *img, u64 span, u64 delta, u64 target)
{
	u64 i;

	for (i = 0; i + 8 <= span; i += 4) {
		u32 insn = rd32(img + i);
		i64 imm;
		u64 page;
		u32 add, imm12;

		if ((insn & 0x9f000000u) != 0x90000000u) {	/* ADRP */
			continue;
		}
		imm = (i64)((((u64)(insn >> 5) & 0x7ffffu) << 2) |
		    ((insn >> 29) & 3u));
		if (imm & (1 << 20)) {
			imm -= (1 << 21);			/* sign-extend */
		}
		page = ((delta + i) & PAGE_MASK) + (u64)(imm << 12);
		if (page != (target & PAGE_MASK)) {
			continue;
		}
		add = rd32(img + i + 4);
		if ((add & 0x7f000000u) != 0x11000000u ||	/* ADD (immediate) */
		    (add & 0x80000000u) == 0u ||		/* 64-bit form */
		    ((add >> 22) & 3u) != 0u ||			/* no shift */
		    (add & 0x1fu) != ((add >> 5) & 0x1fu)) {	/* same register */
			continue;
		}
		imm12 = (add >> 10) & 0xfffu;
		if (page + imm12 == target) {
			return i;
		}
	}
	return (u64)-1;
}

/*
 * Walk back from a reference to the enclosing function's entry: the nearest
 * "pacibsp" (every function in the collection is arm64e and opens with the
 * B-key pair), including a preceding "bti c" when it has one.
 */
static u64 find_function_entry(const u8 *img, u64 ref)
{
	u64 e;

	if (ref < 4) {
		return (u64)-1;
	}
	for (e = ref; e >= 4; e -= 4) {
		if (rd32(img + e) == ARM64_PACIBSP) {
			break;
		}
	}
	if (e < 4) {
		return (u64)-1;
	}
	if (rd32(img + e - 4) == ARM64_BTI_C) {
		e -= 4;
	}
	return e;
}

/* Count "bl" sites that land on a function; record up to `max` of them. */
static u32 find_bl_callers(const u8 *img, u64 span, u64 delta, u64 func,
    u64 *out, u32 max)
{
	u64 i;
	u32 n = 0;

	for (i = 0; i + 4 <= span; i += 4) {
		u32 insn = rd32(img + i);
		i64 imm;

		if ((insn & 0xfc000000u) != 0x94000000u) {	/* BL */
			continue;
		}
		imm = (i64)(insn & 0x03ffffffu);
		if (imm & (1 << 25)) {
			imm -= (1 << 26);			/* sign-extend */
		}
		if ((u64)((i64)(delta + i) + (imm << 2)) == func) {
			if (out && n < max) {
				out[n] = i;
			}
			n++;
		}
	}
	return n;
}

/*
 * Replace a predicate's body with "return false", leaving its BTI landing pad
 * in place.  The stub re-signs the link register with the same B-key/SP pair
 * the real prologue would have used, so it can return through the caller's
 * frame without ever touching SP.
 */
static void write_pretend_false(u8 *img, u64 entry)
{
	u64 at = entry;

	if (rd32(img + at) == ARM64_BTI_C) {
		at += 4;
	}
	wr32(img + at, ARM64_MOV_W0_0);
	wr32(img + at + 4, ARM64_PACIBSP);
	wr32(img + at + 8, ARM64_RETAB);
}

static int patch_apple_root_auth(u8 *img, u64 span, const gh_macho *m)
{
	u64 delta = kc_link_delta(m);
	u64 str, ref, fn, calls[4];
	int applied = 0;

	if (delta == (u64)-1) {
		return 0;
	}

	/* 1. bsd_init()'s call to IOSecureBSDRoot(). */
	str = find_cstring(img, span, "SecureRootName");
	if (str != (u64)-1) {
		ref = find_adrp_add(img, span, delta, delta + str);
		fn = (ref == (u64)-1) ? (u64)-1 : find_function_entry(img, ref);
		if (fn != (u64)-1 &&
		    find_bl_callers(img, span, delta, delta + fn, calls, 4) == 1) {
			wr32(img + calls[0], ARM64_NOP);
			gh_loghex("host root attestation bypassed: ", 1);
			applied++;
		}
	}

	/* 2. APFS's root-hash requirement, answered "no". */
	str = find_cstring(img, span, "is_root_hash_authentication_required");
	if (str != (u64)-1) {
		ref = find_adrp_add(img, span, delta, delta + str);
		fn = (ref == (u64)-1) ? (u64)-1 : find_function_entry(img, ref);
		if (fn != (u64)-1 && rd32(img + fn) == ARM64_BTI_C &&
		    rd32(img + fn + 4) == ARM64_PACIBSP) {
			write_pretend_false(img, fn);
			gh_loghex("root hash authentication relaxed: ", 1);
			applied++;
		}
	}

	return applied;
}

/*
 * Diagnostic handover: run a different program as PID 1.
 *
 * XNU's load_init_program() execs one path -- "/sbin/launchd" in a release
 * kernel -- and no boot-arg or device tree property changes it.  On a machine
 * whose root volume is not (yet) a complete macOS install, that leaves the
 * boot wherever launchd stops, with no way to look around, and the first thing
 * a bring-up needs is a shell.  Linux has init= for exactly this; Gatehouse
 * only edits the image when the caller asks it to (main.c's gh_init=<path>),
 * and never touches the shipped default.
 *
 * The locator proves the byte string it rewrites is the one
 * load_init_program() is about to exec, without hardcoding an address:
 *
 *	1. "load_init_program: attempting to load %s" is the format string of
 *	   the printf() immediately before that exec, and the compiler
 *	   materialises both it and the path argument with the usual
 *	   "adrp xN, <page>; add xN, xN, #<off>" pair, back to back:
 *
 *		adrp	x20, <page>		; the path
 *		add	x20, x20, #<off>
 *		str	x20, [sp]		; argv[0]
 *		adrp	x0, <page>		; the format string
 *		add	x0, x0, #<off>
 *		bl	printf
 *		mov	x0, x20
 *		bl	load_init_program_at_path
 *
 *	   so the path is the adrp+add pair eight bytes before the format
 *	   string's, and the format string itself must be referenced exactly
 *	   once (a second reference means the shape is not what we expect).
 *	2. what that pair resolves to must look like the thing we are about to
 *	   overwrite: a NUL-terminated absolute path in the image.
 *	3. the replacement must fit in the space the shipped path occupies
 *	   (14 bytes plus its NUL), so the strings that follow it -- the kernel
 *	   uses the neighbours too -- are never disturbed.
 *
 * Any deviation from that shape and the image is left alone rather than
 * half-patched.
 */
static const char init_fmt[] =
    "load_init_program: attempting to load %s\n";

/* Decode "adrp xN, <page>"; return the page address, or (u64)-1. */
static u64 adrp_page(const u8 *img, u64 at, u64 delta, u32 *reg)
{
	u32 insn = rd32(img + at);
	i64 imm;

	if ((insn & 0x9f000000u) != 0x90000000u) {
		return (u64)-1;
	}
	imm = (i64)((((u64)(insn >> 5) & 0x7ffffu) << 2) | ((insn >> 29) & 3u));
	if (imm & (1 << 20)) {
		imm -= (1 << 21);
	}
	*reg = insn & 0x1fu;
	return ((delta + at) & PAGE_MASK) + (u64)(imm << 12);
}

/* Decode the "add xN, xN, #imm" that pairs with it; return the address. */
static u64 adrp_add_target(const u8 *img, u64 at, u64 page, u32 reg)
{
	u32 insn = rd32(img + at);

	if ((insn & 0x7f000000u) != 0x11000000u ||	/* ADD (immediate) */
	    (insn & 0x80000000u) == 0u ||		/* 64-bit form */
	    ((insn >> 22) & 3u) != 0u ||			/* no shift */
	    (insn & 0x1fu) != reg ||			/* destination ... */
	    ((insn >> 5) & 0x1fu) != reg) {		/* ... and source */
		return (u64)-1;
	}
	return page + ((insn >> 10) & 0xfffu);
}

int gh_patch_init_program(u8 *img, u64 span, const gh_macho *m,
    const char *path)
{
	u64 delta = kc_link_delta(m);
	u64 fstr, first = (u64)-1, page, str = (u64)-1;
	u64 i, k, n, orig, hits;
	u32 refs = 0, reg;

	if (delta == (u64)-1 || path == 0 || path[0] != '/') {
		return 0;
	}
	n = gh_strlen(path);

	/* The format string must exist and be referenced exactly once. */
	fstr = find_cstring(img, span, init_fmt);
	if (fstr == (u64)-1) {
		return 0;
	}
	for (i = 0; i + 8 <= span; i += 4) {
		u32 r;

		page = adrp_page(img, i, delta, &r);
		if (page == (u64)-1) {
			continue;
		}
		if (adrp_add_target(img, i + 4, page, r) == delta + fstr) {
			refs++;
			if (first == (u64)-1) {
				first = i;
			}
		}
	}
	if (refs != 1) {
		return 0;
	}

	/*
	 * The path is materialised by its own adrp+add just ahead of the
	 * format string's -- with the argv[0] store between the two pairs --
	 * so walk back over the instructions preceding the format reference
	 * and keep the pair that really does resolve to a NUL-terminated
	 * absolute path.  Exactly one of them may, or the shape is not the one
	 * this patch was written against.
	 */
	for (hits = 0, k = 1; k <= 6 && first >= 4 * k; k++) {
		u64 at = first - 4 * k, cand, off;

		page = adrp_page(img, at, delta, &reg);
		if (page == (u64)-1) {
			continue;
		}
		cand = adrp_add_target(img, at + 4, page, reg);
		if (cand == (u64)-1 || cand < delta) {
			continue;
		}
		off = cand - delta;
		if (off >= span || img[off] != '/') {
			continue;
		}
		for (orig = 0; off + orig < span && img[off + orig] != 0 &&
		    orig < 256; orig++) {
		}
		if (orig == 0 || orig == 256) {
			continue;
		}
		hits++;
		str = cand;
	}
	if (hits != 1) {
		return 0;
	}
	i = str - delta;				/* image offset of the path */
	for (orig = 0; i + orig < span && img[i + orig] != 0 &&
	    orig < 256; orig++) {
	}

	/* The replacement has to fit in the space the shipped path occupies,
	 * so the strings that follow it are never disturbed. */
	if (n > orig) {
		return 0;
	}

	gh_memcpy(img + i, path, n + 1);

	return 1;
}

int gh_patch_kernel(u8 *img, u64 span, const gh_macho *m)
{
	int applied = 0;

	/* Apple VM platform hypercalls (see above). */
	applied += patch_apple_hypercalls(img, span);

	/* IOPCIDevice::extendedFindPCICapability() fast path (see above). */
	applied += patch_apple_pci_capability_search(img, span);

	/* Root-volume authentication with no host attestation (see above). */
	applied += patch_apple_root_auth(img, span, m);

	return applied;
}
