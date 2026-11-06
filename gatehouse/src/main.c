// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/main.c - Gatehouse, the HackintARM ARM64 bootloader.
 *
 * Milestone 1: on QEMU `virt` + AAVMF, load an XNU kernelcache (arm64e), build
 * an XNU `boot_args`, provide a device tree, drop to EL1, and transfer control
 * to the kernel.  Everything here is designed to run unchanged on a real SoC:
 * nothing reads a QEMU-specific register or hard-codes a virtual-only device
 * beyond the device tree we *hand* to the kernel.
 */
#include "gh.h"
#include "version.h"

static EFI_SYSTEM_TABLE *ST;
static EFI_BOOT_SERVICES *BS;

/* Where the kernel image lands (V=P), chosen from the machine's RAM at run
 * time: the middle of the largest usable run, adjusted so the mach header
 * keeps the link-time congruence XNU's bootstrap mapping requires.  There is
 * deliberately no fixed base: a real machine may put RAM anywhere. */
/* L2 block size for XNU's bootstrap page tables (16 KB granule). */
#define GH_BOOT_L2_BLOCK    0x2000000ULL
#define GH_DT_MAX           0x00100000ULL  /* 1 MiB device tree ceiling */

/* iBoot's panic region.  XNU's check_for_panic_log() (pexpert/arm/pe_init.c)
 * reads its physical address from the ADT's /pram "reg" property and the size
 * from /chosen/embedded-panic-log-size, then maps it write-combined and uses
 * it for the embedded panic header and the panic log.  PE_update_panicheader_
 * nestedpanic() asserts ("Assertion failed: panic_info") when it is absent,
 * and _doprnt()ing the panic text to the console needs the header too.
 *
 * We place it above the image and boot data, inside the boot-data window that
 * main() reserves between the image and topOfKernelData: XNU never hands that
 * window to the VM allocator, so the log survives.  The offset must clear the
 * largest image we ever load -- a macOS 27 VMApple kernel collection is 81.4
 * MiB -- plus the device tree and boot_args, hence 88 MiB here.
 * build_adt.py emits the same offset as a placeholder; Gatehouse overwrites
 * /pram with the address the image actually landed at. */
#define GH_PANIC_OFF        0x05800000ULL  /* from the image base (88 MiB) */
#define GH_PANIC_SIZE       0x00080000ULL  /* 512 KiB, as iBoot uses */

/* debug flags: 0x100 DB_KDP_GETC_ENA, 0x40 DB_KDP_BP_DIS, 0x08 DB_KPRT,
 * 0x04 DB_NMI, 0x02 DB_PRT.  DB_KPRT|DB_PRT make XNU emit its early boot log
 * on the serial console, which is our only window into the kernel before the
 * IOKit console driver exists. */
/* -noprogress: PE_init_iokit() (pexpert/arm/pe_init.c) defaults show_progress
 * to TRUE on macOS and then walks default_progress.dy away from
 * display_size / 2.  Our boot_args carry no Video geometry (there is no
 * display in the ADT), so display_size is 0, the loop condition never fails
 * and the assert(*delta >= 0) trap fires.  A real vmapple guest has a
 * paravirtualised display; we simply have nothing to draw on. */
/* serial=: XNU's pexpert decode of the boot-arg into `serialmode`
 * (osfmk/console/serial_protos.h) bit 0x01 = SERIALMODE_OUTPUT, 0x02 =
 * SERIALMODE_INPUT, 0x08 = SERIALMODE_BASE_TTY.  Output alone gives the
 * kernel's own printf and nothing else; SERIALMODE_INPUT is what starts
 * serial_keyboard_init()'s polling thread (osfmk/console/serial_general.c),
 * the only thing that ever feeds characters into the BSD console queue, and
 * XNU only exposes hw.serialdebugmode -- the sysctl launchd reads to decide
 * whether to load the serial console job -- when output *and* input are both
 * set (bsd/kern/kern_mib.c).  With serial=1 there is no way in at all.
 *
 * cpus= is deliberately *not* here: the machine's CPU count is chosen once,
 * in the device tree, and the command line carries it back out of that same
 * tree (see the /cpus count below).  A compiled-in number could disagree with
 * the tree the machine published, and ml_parse_cpu_topology() would then take
 * the boot arg's word over the hardware. */
#define GH_CMD_LINE         "debug=0x14e -v -noprogress serial=3 kextlog=0xfff keepsyms=1 exe_boothash_salt=0"

/* ------------------------------------------------------------------ */

static void putc_(char c) { gh_uart_putc(c); }
static void puts_(const char *s) { gh_uart_puts(s); }
static void nl(void) { gh_uart_putc('\n'); }

static void print_ucs2(const CHAR16 *s)
{
	for (; *s; s++) {
		CHAR16 c = *s;
		putc_(c < 0x80 ? (char)c : '?');
	}
}

static void ucs2_to_ascii(char *dst, const CHAR16 *src, u64 cap)
{
	u64 i = 0;
	if (cap == 0) {
		return;
	}
	for (; src[i] && i + 1 < cap; i++) {
		dst[i] = src[i] < 0x80 ? (char)src[i] : '?';
	}
	dst[i] = 0;
}

static void banner(void)
{
	char ver[8];

	puts_("\n");
	puts_("Gatehouse ");
	puts_(gh_version_string(ver));
	puts_(", built with " GH_COMPILER " at " GH_BUILD_DATE " " GH_BUILD_TIME
	    ", running on ");
	print_ucs2(ST->FirmwareVendor);
	nl();
	puts_("---------------------------------\n");
	puts_("UEFI stage. Target: XNU arm64e (macOS 27).\n\n");
	gh_loghex("system table    : ", (u64)ST);
	gh_loghex("boot services   : ", (u64)BS);
	gh_loghex("firmware rev    : ", (u64)ST->FirmwareRevision);
	gh_loghex("exception level : ", gh_current_el());
}

static void dump_config_tables(void)
{
	UINTN i;
	gh_uart_puts("config tables   : ");
	gh_uart_putdec(ST->NumberOfTableEntries);
	nl();
	for (i = 0; i < ST->NumberOfTableEntries; i++) {
		EFI_GUID *g = &ST->ConfigurationTable[i].VendorGuid;
		gh_uart_puts("  ");
		gh_uart_puthex(g->Data1);
		gh_uart_puts("-");
		gh_uart_puthex(((u64)g->Data2 << 16) | g->Data3);
		gh_uart_puts("-");
		gh_uart_puthex(((u64)g->Data4[0] << 8) | g->Data4[1]);
		gh_uart_puts(" ");
		gh_uart_puthex((u64)ST->ConfigurationTable[i].VendorTable);
		nl();
	}
}

/* ------------------------------------------------------------------ */

static EFI_FILE_PROTOCOL *open_root(void)
{
	EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
	EFI_HANDLE *handles = 0;
	UINTN n = 0, i;
	EFI_STATUS s;
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
	EFI_FILE_PROTOCOL *root;

	s = BS->LocateHandleBuffer(2 /* ByProtocol */, &fs_guid, 0, &n, &handles);
	if (EFI_ERROR(s) || !handles || !n) {
		gh_loghex("LocateHandleBuffer failed: ", s);
		return 0;
	}
	for (i = 0; i < n; i++) {
		s = BS->HandleProtocol(handles[i], &fs_guid, (void **)&fs);
		if (EFI_ERROR(s)) {
			continue;
		}
		s = fs->OpenVolume(fs, &root);
		if (!EFI_ERROR(s)) {
			return root;
		}
	}
	gh_log("no SimpleFileSystem volume found\n");
	return 0;
}

/* Read a whole file into a freshly allocated pool buffer.  `quiet` exists for
 * the optional handover files (the ramdisk, the second trust cache): an
 * ordinary boot legitimately has neither, and "open failed" for every one of
 * them would bury the lines that matter. */
static void *read_file_opt(EFI_FILE_PROTOCOL *root, const CHAR16 *path,
    u64 *out_size, int quiet)
{
	EFI_FILE_PROTOCOL *f;
	EFI_GUID info_id = EFI_FILE_INFO_ID;
	EFI_STATUS s;
	EFI_FILE_INFO *info;
	UINTN info_sz = 0;
	void *buf = 0;
	UINTN rsz;

	s = root->Open(root, &f, (CHAR16 *)path, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(s)) {
		if (!quiet) {
			puts_("open failed: ");
			print_ucs2(path);
			gh_loghex(" status ", s);
		}
		return 0;
	}
	/* query size */
	s = f->GetInfo(f, &info_id, &info_sz, 0);
	if (s != EFI_BUFFER_TOO_SMALL || info_sz < sizeof(EFI_FILE_INFO)) {
		gh_loghex("GetInfo(size) failed: ", s);
		return 0;
	}
	info_sz += 64;
	s = BS->AllocatePool(2 /* EfiLoaderData */, info_sz, (void **)&info);
	if (EFI_ERROR(s)) {
		gh_loghex("AllocatePool(info) failed: ", s);
		return 0;
	}
	s = f->GetInfo(f, &info_id, &info_sz, info);
	if (EFI_ERROR(s)) {
		gh_loghex("GetInfo failed: ", s);
		return 0;
	}
	*out_size = info->FileSize;
	BS->FreePool(info);

	s = BS->AllocatePool(2, (UINTN)*out_size, &buf);
	if (EFI_ERROR(s)) {
		gh_loghex("AllocatePool(file) failed: ", s);
		return 0;
	}
	rsz = (UINTN)*out_size;
	s = f->Read(f, &rsz, buf);
	if (EFI_ERROR(s) || rsz != *out_size) {
		gh_loghex("Read short/failed: ", s);
		gh_loghex("  bytes read: ", rsz);
	}
	f->Close(f);
	return buf;
}

static void *read_file(EFI_FILE_PROTOCOL *root, const CHAR16 *path,
    u64 *out_size)
{
	return read_file_opt(root, path, out_size, 0);
}

/* ------------------------------------------------------------------ */

/*
 * Ask the firmware to make a range executable (and writable).  AAVMF maps
 * EfiLoaderData as no-execute, so the kernel image we just copied would fault
 * on its first instruction fetch.  On real hardware the loader owns the page
 * tables, but under UEFI we must go through the memory attribute protocol.
 */
static void *find_config_table(EFI_GUID *want)
{
	UINTN i;
	if (!ST->ConfigurationTable) {
		return 0;
	}
	for (i = 0; i < ST->NumberOfTableEntries; i++) {
		EFI_GUID *g = &ST->ConfigurationTable[i].VendorGuid;
		if (g->Data1 == want->Data1 && g->Data2 == want->Data2 &&
		    g->Data3 == want->Data3 &&
		    *(u32 *)g->Data4 == *(u32 *)want->Data4 &&
		    *(u32 *)(g->Data4 + 4) == *(u32 *)(want->Data4 + 4)) {
			return ST->ConfigurationTable[i].VendorTable;
		}
	}
	return 0;
}

static int make_range_executable(u64 base, u64 size)
{
	EFI_GUID g = EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID;
	EFI_MEMORY_ATTRIBUTE_PROTOCOL *p = 0;
	EFI_GUID dxe_g = EFI_DXE_SERVICES_TABLE_GUID;
	EFI_DXE_SERVICES *dxe;
	EFI_STATUS s;

	/* Preferred: the UEFI 2.10 memory attribute protocol. */
	s = BS->LocateProtocol(&g, 0, (void **)&p);
	if (!EFI_ERROR(s) && p) {
		s = p->ClearMemoryAttributes(p, base, size, EFI_MEMORY_XP | EFI_MEMORY_RO);
		gh_loghex("clear XN|RO      : ", s);
		if (!EFI_ERROR(s)) {
			return 0;
		}
	}

	/* Fallback: the PI DXE services table (AAVMF has no attribute proto).
	 * EDK2/ArmVirt does install it; locate it by its leading Data1 only,
	 * since firmware variants vary the remaining fields. */
	dxe = 0;
	if (ST->ConfigurationTable) {
		UINTN i;
		for (i = 0; i < ST->NumberOfTableEntries; i++) {
			if (ST->ConfigurationTable[i].VendorGuid.Data1 == 0x05ad34baU) {
				dxe = (EFI_DXE_SERVICES *)ST->ConfigurationTable[i].VendorTable;
				break;
			}
		}
	}
	if (!dxe || !dxe->SetMemorySpaceAttributes) {
		gh_log("no DXE services table either\n");
		return -1;
	}
	s = dxe->SetMemorySpaceAttributes(base, size, EFI_MEMORY_WB);
	gh_loghex("set WB(RWX)      : ", s);
	return EFI_ERROR(s) ? -1 : 0;
}

/* ------------------------------------------------------------------ */

static u32 rd32le(const u8 *p)
{
	return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static void wr32le(u8 *p, u32 v)
{
	p[0] = (u8)(v & 0xff);
	p[1] = (u8)((v >> 8) & 0xff);
	p[2] = (u8)((v >> 16) & 0xff);
	p[3] = (u8)((v >> 24) & 0xff);
}

static u64 rd64le(const u8 *p)
{
	return (u64)rd32le(p) | ((u64)rd32le(p + 4) << 32);
}

static void wr64le(u8 *p, u64 v)
{
	wr32le(p, (u32)v);
	wr32le(p + 4, (u32)(v >> 32));
}

/* Read one DER TLV.  IMG4 uses definite lengths only (short form or
 * 0x81/0x82/0x83), which is all Apple emits and all we need. */
static int der_next(const u8 **pp, const u8 *end, u8 *tag,
    const u8 **val, u64 *len)
{
	const u8 *p = *pp;
	u64 l;
	unsigned n, i;

	if (p >= end)
		return -1;
	*tag = *p++;
	if (p >= end)
		return -1;
	l = *p++;
	if (l & 0x80) {
		n = (unsigned)(l & 0x7F);
		if (n == 0 || n > 4 || (u64)(end - p) < n)
			return -1;
		l = 0;
		for (i = 0; i < n; i++)
			l = (l << 8) | *p++;
	}
	if (l > (u64)(end - p))
		return -1;
	*val = p;
	*len = l;
	*pp = p + l;
	return 0;
}

/*
 * Unwrap an IMG4 object of the given payload type ("trst" for a trust cache,
 * "rdsk" for a restore ramdisk) to the payload iBoot verifies and hands to the
 * kernel.  A file that is not an IMG4 wrapper is taken to be the payload
 * itself, so a raw object works too.
 */
static int img4_payload(const u8 *file, u64 fsize, const char *type4,
    const u8 **payload, u64 *plen)
{
	const u8 *p = file, *end = file + fsize, *v, *seq_end;
	u8 tag;
	u64 l;

	if (fsize >= 4 && file[0] == 0x30 &&
	    der_next(&p, end, &tag, &v, &l) == 0 && tag == 0x30) {
		seq_end = v + l;
		p = v;
		/* "IM4P": the container type */
		if (der_next(&p, seq_end, &tag, &v, &l) || tag != 0x16 ||
		    l != 4 || gh_memcmp(v, "IM4P", 4))
			return -1;
		/* the payload type; only the one we asked for is accepted */
		if (der_next(&p, seq_end, &tag, &v, &l) || tag != 0x16 ||
		    l != 4 || gh_memcmp(v, type4, 4))
			return -1;
		/* the object's version string */
		if (der_next(&p, seq_end, &tag, &v, &l) || tag != 0x16)
			return -1;
		/* the payload blob */
		if (der_next(&p, seq_end, &tag, &v, &l) || tag != 0x04)
			return -1;
		*payload = v;
		*plen = l;
		return 0;
	}
	*payload = file;
	*plen = fsize;
	return 0;
}

/*
 * Hand XNU the static trust caches, the way iBoot does.
 *
 * load_static_trust_cache() (bsd/kern/kern_trustcache.c) reads
 * /chosen/memory-map/TrustCache as a { paddr, length } pair and treats that
 * physical range as a trust_cache_offsets_t: a count followed by that many
 * byte offsets to the individual cache modules.
 *
 *     u32 num_caches; u32 offsets[num_caches]; <modules>
 *
 * A module is the IMG4 payload itself (version, uuid, entry count, entries) --
 * iBoot verifies the wrapper and the kernel never sees it.  The entry is
 * published by the caller after this returns.
 *
 * Only offsets[0] is loaded as the *static* trust cache; the rest are
 * "engineering" modules, which arm64 release kernels skip unless a boot-arg
 * opens them up.  So the cache that matters goes first, and which one that is
 * depends on what is about to become the root device: an ordinary boot runs
 * the platform binaries, a rooted ramdisk runs the restore environment, and
 * each is vouched for by a different cache (they are not interchangeable --
 * both name individual cdhashes).
 *
 * The range has to sit *below* the kernel image, because arm_vm_prot_init()
 * (osfmk/arm64/arm_vm_init.c) insists on it:
 *
 *     if (trustCacheRegion < segLOWEST) { ...EXTRADATA... }
 *     else { panic("TrustCache region is in an unexpected place"); }
 *
 * on release kernels, where segLOWEST is the kernel collection's mach header.
 * That is also the window iBoot describes in boot_args: physBase/virtBase name
 * the bottom of the boot data, not the kernel, and start.s moves both up to
 * the mach header for its own bootstrap mapping.  So the cache is allocated
 * immediately below the image, and the caller lowers the boot_args window base
 * to cover it.
 */
static int load_trust_cache(EFI_FILE_PROTOCOL *root, u64 img, int ramdisk_root,
    u64 *out_phys, u64 *out_len)
{
	/*
	 * Ordered by what will be the root device; see above.  The IMG4 payload
	 * type differs between the two: AppleImage4 wraps the platform's static
	 * cache as "trst" (trust cache) but the one generated for a restore
	 * ramdisk as "rtsc".  Both unwrap to the same trust_cache_offsets_t
	 * module, so only the wrapper matters.
	 */
	static const CHAR16 *paths[2] = {
		L"\\gatehouse\\ramdisktc",
		L"\\gatehouse\\trustcache",
	};
	static const char *types[2] = { "rtsc", "trst" };
	const u8 *payload[2];
	u64 plen[2];
	int i, j, n = 0;
	u64 hdr, need, base, off;
	u8 *dst;

	for (i = 0; i < 2; i++) {
		/* Module 0 is the static cache: the ramdisk's when it is going
		 * to be the root device, the platform's otherwise. */
		int k = (i == 0) ? (ramdisk_root ? 0 : 1)
		    : (ramdisk_root ? 1 : 0);
		u8 *file;
		u64 fsize = 0;
		u32 ver, count, esz;

		file = read_file_opt(root, paths[k], &fsize, 1);
		if (!file) {
			continue;
		}
		if (img4_payload((const u8 *)file, fsize, types[k],
		    &payload[n], &plen[n]) != 0 || plen[n] < 24) {
			gh_log("trust cache     : not an IMG4 trust cache object\n");
			continue;
		}
		ver = rd32le(payload[n]);
		count = rd32le(payload[n] + 20);
		esz = (ver == 1) ? 22 : (ver == 2) ? 24 : 0;
		if (!esz || 24 + (u64)count * esz != plen[n]) {
			gh_loghex("trust cache     : unsupported object ", ver);
			continue;
		}
		gh_loghex(k ? "trust cache     : platform entries "
		    : "trust cache     : ramdisk entries ", count);
		n++;
	}
	if (!n) {
		gh_log("trust cache     : not provided\n");
		return -1;
	}

	/* num_caches, then one u32 offset per module, then the modules
	 * themselves, each aligned so its version field is naturally aligned. */
	hdr = 4 + 4 * (u64)n;
	need = hdr;
	for (i = 0; i < n; i++) {
		need = (need + 7) & ~7ULL;
		need += plen[i];
	}
	*out_len = need;
	need = (need + GH_PAGE - 1) & ~(GH_PAGE - 1);

	/*
	 * Walk down from just below the image until the firmware lets us have
	 * the pages.  The steps are one L2 block, so the window base stays close
	 * to the kernel: arm_vm_prot_init() maps [physBase, segLOWEST) with the
	 * bootstrap L1 table, which only exists for the kernel's own gigabyte.
	 */
	base = (img - need) & ~(GH_PAGE - 1);
	for (j = 0; j < 32; j++, base -= GH_BOOT_L2_BLOCK) {
		EFI_PHYSICAL_ADDRESS pa = base;

		if (!EFI_ERROR(BS->AllocatePages(2 /* AllocateAddress */,
		    2 /* EfiLoaderData */, need / GH_EFI_PAGE, &pa))) {
			break;
		}
	}
	if (j == 32) {
		gh_log("trust cache     : no free pages below the image\n");
		return -1;
	}

	dst = (u8 *)base;
	gh_memset(dst, 0, need);
	wr32le(dst, (u32)n);
	off = hdr;
	for (i = 0; i < n; i++) {
		off = (off + 7) & ~7ULL;
		wr32le(dst + 4 + 4 * (u64)i, (u32)off);
		gh_memcpy(dst + off, payload[i], plen[i]);
		off += plen[i];
	}

	gh_loghex("trust cache     : ", base);
	gh_loghex("trust cache len : ", *out_len);
	gh_uart_puts("trust cache mods: ");
	gh_uart_putdec((u64)n);
	nl();
	*out_phys = base;
	return 0;
}


/*
 * iBoot's other handover for a restore boot: the ramdisk.  Returns the
 * payload (the APFS container) and its length, or 0 when the ESP has none.
 *
 * XNU's IOKitBSDInit turns /chosen/memory-map/RAMDisk into /dev/md0, and the
 * boot argument "rd=md0" makes that the root device (bsd_rooted_ramdisk(),
 * bsd/kern/bsd_init.c) -- which also routes around the whole root-volume
 * authentication path.  The bytes themselves are copied into the boot window
 * by load_and_jump(); see the layout comment there for why they have to live
 * inside it.
 */
static u64 read_ramdisk(EFI_FILE_PROTOCOL *root, const u8 **payload)
{
	u64 fsize = 0, plen = 0;
	u8 *file = read_file_opt(root, L"\\gatehouse\\ramdisk", &fsize, 1);

	if (!file) {
		return 0;
	}
	if (img4_payload((const u8 *)file, fsize, "rdsk", payload, &plen) != 0 ||
	    plen < GH_PAGE) {
		gh_log("ramdisk         : not an IMG4 rdsk object\n");
		return 0;
	}
	return plen;
}

static int load_and_jump(void)
{
	EFI_FILE_PROTOCOL *root;
	void *kfile = 0, *dtfile = 0;
	u64 ksize = 0, dtsize = 0;
	gh_macho m;
	u64 span, alloc_sz, npages;
	u64 dt_off, ba_off, boot_off, panic_off, top_off;
	EFI_PHYSICAL_ADDRESS img = 0;
	EFI_STATUS s;
	u64 dt_phys, ba_phys, top_of_kernel;
	u8 *p;
	u64 tc_phys = 0, tc_len = 0;
	const u8 *rd_payload = 0;
	u64 rd_len = 0, rd_off = 0;
#ifdef GH_LANTERN_HOST_TRANSPORT
	u64 mb_off = 0;
#endif
	int init_arg = 0;

	root = open_root();
	if (!root) {
		return -1;
	}

	kfile = read_file(root, L"\\gatehouse\\kernel", &ksize);
	if (!kfile) {
		gh_log("kernel read failed\n");
		return -1;
	}
	gh_loghex("kernel file size: ", ksize);

	if (gh_macho_parse(&m, (const u8 *)kfile, ksize) != 0) {
		gh_log("macho parse failed\n");
		return -1;
	}
	gh_loghex("link base       : ", m.link_base);
	gh_loghex("entry (VA)      : ", m.entry);
	gh_loghex("image span      : ", m.text_size);
	gh_uart_puts("segments        : ");
	gh_uart_putdec(m.nsegs);
	nl();
	if (m.is_fileset) {
		gh_uart_puts("image kind      : kernel collection (MH_FILESET)\n");
		gh_loghex("fileset slices  : ", m.nfileset);
		gh_loghex("kernel slice VA : ", m.kslice_vmaddr);
	}

	/*
	 * One contiguous window, laid out so that XNU's "everything below
	 * topOfKernelData belongs to the kernel" rule keeps the panic region
	 * alive:
	 *
	 *   [trust cache][image][device tree][boot_args] ... [panic log][ramdisk]
	 *
	 * The panic region sits at a fixed offset from the image base, and
	 * Gatehouse writes /pram from the address the image actually landed
	 * at (the tree is a template, not a layout).
	 *
	 * A restore ramdisk, when the ESP carries one, goes above the panic log
	 * and inside the same window: arm_vm_physmap_init() maps everything from
	 * end_kern up to topOfKernelData in one go -- "Device Tree (if not
	 * locked down), RAM Disk (if present), bootArgs" -- and hands only what
	 * is above topOfKernelData to the VM layer.  A ramdisk anywhere else is
	 * free memory that the allocator reissues underneath the guest.
	 */
	span = (m.text_size + GH_PAGE - 1) & ~(GH_PAGE - 1);
	dt_off = span;
	ba_off = (dt_off + GH_DT_MAX + GH_PAGE - 1) & ~(GH_PAGE - 1);
	boot_off = ba_off + GH_PAGE * 4;
	panic_off = GH_PANIC_OFF;
	if (panic_off < boot_off) {
		gh_log("panic region collides with boot data\n");
		return -1;
	}
	top_off = (panic_off + GH_PANIC_SIZE + GH_PAGE - 1) & ~(GH_PAGE - 1);
	rd_len = read_ramdisk(root, &rd_payload);
	if (rd_len) {
		rd_off = top_off;
		top_off = (rd_off + rd_len + GH_PAGE - 1) & ~(GH_PAGE - 1);
	}
#ifdef GH_LANTERN_HOST_TRANSPORT
	/*
	 * Lantern's host mailbox rides at the end of the same reserved window.
	 * That window is what boot_args calls topOfKernelData, so XNU maps it
	 * but never gives it to the VM allocator: the page survives the boot
	 * without carving a hole in the machine's DRAM window.
	 */
	mb_off = top_off;
	top_off += GH_PAGE;
#endif
	/*
	 * AllocatePages() counts 4 KiB pages whatever the CPU's translation
	 * granule is, so the count must use GH_EFI_PAGE.  GH_PAGE stays in the
	 * alignment arithmetic below, where XNU's 16 KiB granule is what matters.
	 */
	alloc_sz = top_off;
	npages = (alloc_sz + GH_EFI_PAGE - 1) / GH_EFI_PAGE;

	/*
	 * Ask the firmware what RAM this machine has.  Everything below --
	 * the kernel window, /chosen dram-base and dram-size, the stage-2
	 * map -- is derived from this answer; no build-time constant guesses
	 * the machine.
	 */
	if (gh_memory_discover(BS) != 0) {
		gh_log("cannot determine the machine's RAM\n");
		return -1;
	}
	gh_loghex("RAM base        : ", gh_memory_base());
	gh_loghex("RAM top         : ", gh_memory_top());

	/*
	 * Pick the physical base of the kernel image.  The constraints are in
	 * the block below; the short version is that the mach header's
	 * physical address has to be congruent to its link address modulo the
	 * L2 block size, and the whole window has to fit in the machine's RAM.
	 */
	{
		/*
		 * XNU builds its bootstrap KVA mapping out of L2 block
		 * descriptors (32 MB with the 16 KB granule) and maps
		 * virtualBase to physBase one block at a time.  It also
		 * computes every kernel address as "physical + (virtualBase -
		 * physBase)", while the addresses baked into the Mach-O are
		 * the virtual ones.  Together those force the physical base of
		 * the mach header to be congruent to the link base modulo the
		 * L2 block size; iBoot guarantees this on real hardware and
		 * XNU is entitled to assume it.  A 16 KB offset here silently
		 * shifts the whole KVA mapping into unmapped memory, so every
		 * candidate is congruent by construction.
		 *
		 * The middle of the machine's RAM is the first choice: it
		 * leaves the largest possible room above for firmware runtime
		 * data and below for the banner and boot objects, and it is
		 * where iBoot's own layout lands on the bring-up machine.
		 * Firmware may already own pages there, so walk outwards until
		 * the allocation succeeds, staying inside the RAM window.
		 */
		const u64 plane = GH_BOOT_L2_BLOCK;
		const u64 low = m.link_base & (plane - 1);
		const u64 base = gh_memory_base();
		const u64 top = gh_memory_top();
		u64 lo_lim, up_lim, lim, cand, c;
		int found = 0;

		if (low & (GH_PAGE - 1)) {
			gh_log("kernel window: link base is not 16K aligned\n");
			return -1;
		}
		if (top <= base || alloc_sz > top - base) {
			gh_log("kernel window: does not fit in RAM\n");
			return -1;
		}

		/* Smallest/largest congruent addresses that still fit. */
		lim = top - alloc_sz;
		if (lim < low) {
			gh_log("kernel window: no congruent address fits\n");
			return -1;
		}
		lo_lim = (base & ~(plane - 1)) + low;
		if (lo_lim < base)
			lo_lim += plane;
		up_lim = (lim & ~(plane - 1)) + low;
		if (up_lim > lim) {
			if (up_lim < plane) {
				gh_log("kernel window: no congruent address fits\n");
				return -1;
			}
			up_lim -= plane;
		}

		cand = ((base + (top - base) / 2) & ~(plane - 1)) + low;
		if (cand < lo_lim)
			cand = lo_lim;
		if (cand > up_lim)
			cand = up_lim;
		if (cand < lo_lim) {
			gh_log("kernel window: no congruent address fits\n");
			return -1;
		}

		for (c = cand; c >= lo_lim && c <= up_lim; c -= plane) {
			EFI_PHYSICAL_ADDRESS pa = c;

			s = BS->AllocatePages(2 /* AllocateAddress */,
			    1 /* EfiLoaderCode */, npages, &pa);
			if (!EFI_ERROR(s)) {
				img = c;
				found = 1;
				break;
			}
			if (c < plane)
				break;
		}
		if (!found) {
			for (c = cand + plane; c <= up_lim; c += plane) {
				EFI_PHYSICAL_ADDRESS pa = c;

				s = BS->AllocatePages(2 /* AllocateAddress */,
				    1 /* EfiLoaderCode */, npages, &pa);
				if (!EFI_ERROR(s)) {
					img = c;
					found = 1;
					break;
				}
			}
		}
		if (!found) {
			gh_log("no free RAM for the kernel window\n");
			return -1;
		}
	}
	gh_loghex("image phys      : ", img);

	if (gh_macho_load_flat(&m, img, &top_of_kernel) != 0) {
		gh_log("flat load failed\n");
		return -1;
	}
	gh_loghex("top of kernel   : ", top_of_kernel);
#ifdef GH_LANTERN_HOST_TRANSPORT
	if (gh_lantern_mailbox_init(img + mb_off) != 0)
		return -1;
#endif
	if (rd_len) {
		gh_memcpy((u8 *)img + rd_off, rd_payload, rd_len);
		gh_loghex("ramdisk         : ", img + rd_off);
		gh_loghex("ramdisk size    : ", rd_len);
	}

	/*
	 * Complete the load.  An ordinary kernel is linked but not relocated:
	 * its pointers are still in their encoded LC_DYLD_CHAINED_FIXUPS form
	 * and resolving them is what iBoot does before jumping into a raw
	 * kernel (arm_init dereferences one a few hundred instructions in).
	 *
	 * A kernel collection is different: everything in it is already
	 * resolved against the collection base and XNU *itself* walks the
	 * chains, PAC-signing each rebase with the VA configuration its own
	 * start.s installed (arm_slide_rebase_and_sign_image ->
	 * kernel_collection_slide).  Fixing it up here would sign it under
	 * UEFI's VA size and break every authenticated pointer in the image.
	 */
	if (m.is_fileset) {
		gh_log("chained fixups  : deferred to XNU (kernel collection)\n");
	} else {
		gh_apply_fixups(&m, (u8 *)img);
	}

	/* Deliberate deviations from the shipped image (see patch.c). */
	{
		int np = gh_patch_kernel((u8 *)img, span, &m);
		gh_loghex("kernel patches  : ", (u64)np);
	}

	/*
	 * Bring-up handover (see patch.c): an optional one-line file on the
	 * ESP naming the program to run as PID 1.  Present only while a machine
	 * is being brought up -- a complete root volume does not need it -- and
	 * absent by default, so an ordinary boot runs launchd.
	 */
	{
		char init[64];
		u64 fsize = 0;
		u8 *file = read_file(root, L"\\gatehouse\\init", &fsize);

		if (file) {
			u64 n = 0;

			while (n < fsize && (file[n] == ' ' || file[n] == '\t')) {
				n++;
			}
			gh_memcpy(init, file, fsize - n < sizeof(init) - 1 ?
			    fsize - n : sizeof(init) - 1);
			init[fsize - n < sizeof(init) - 1 ? fsize - n :
			    sizeof(init) - 1] = 0;
			for (n = 0; init[n] && init[n] != '\n' &&
			    init[n] != '\r'; n++) {
			}
			init[n] = 0;
			if (n) {
				gh_log("init override   : ");
				gh_log(init);
				nl();
				gh_loghex("init override   : ",
				    (u64)gh_patch_init_program((u8 *)img, span,
				    &m, init));
			}
			if (n) {
				/*
				 * XNU gives PID 1 one argument, and only when
				 * RB_SINGLE is set.  A rescue shell wants a
				 * path there ("sh /dev/console"), so that it
				 * opens the console itself -- PID 1 starts
				 * with no descriptors, so nothing else can
				 * read the console for it.
				 */
				char initarg[64];
				u64 asize = 0;
				u8 *afile = read_file_opt(root,
				    L"\\gatehouse\\initarg", &asize, 1);

				if (afile) {
					u64 k = 0;

					while (k < asize && (afile[k] == ' ' ||
					    afile[k] == '\t')) {
						k++;
					}
					gh_memcpy(initarg, afile,
					    asize - k < sizeof(initarg) - 1 ?
					    asize - k : sizeof(initarg) - 1);
					initarg[asize - k < sizeof(initarg) - 1 ?
					    asize - k : sizeof(initarg) - 1] = 0;
					for (k = 0; initarg[k] &&
					    initarg[k] != '\n' &&
					    initarg[k] != '\r'; k++) {
					}
					initarg[k] = 0;
					if (k) {
						gh_log("init argument   : ");
						gh_log(initarg);
						nl();
						init_arg =
						    gh_patch_init_argument(
						    (u8 *)img, span, top_off,
						    &m, initarg, boot_off);
						gh_loghex("init argument   : ",
						    (u64)init_arg);
					}
				}
			}
		}
	}

	/*
	 * The device tree, in Apple's encoding (see dt/build_adt.py): XNU's
	 * pexpert parses boot_args->deviceTreeP as an ADT, not as a .dtb.
	 */
	dt_phys = img + dt_off;
	dtfile = read_file(root, L"\\gatehouse\\gatehouse.adt", &dtsize);
	if (dtfile && dtsize) {
		if (dtsize > GH_DT_MAX) {
			gh_log("device tree too large, truncating\n");
			dtsize = GH_DT_MAX;
		}
		gh_memcpy((void *)dt_phys, dtfile, dtsize);
		gh_loghex("device tree     : ", dt_phys);
		gh_loghex("device tree size: ", dtsize);
	} else {
		gh_log("no device tree provided\n");
		dtsize = 0;
		dt_phys = 0;
	}

	/*
	 * iBoot's other job for the kernel's trust caches: find the static cache
	 * the boot chain is willing to vouch for, put it in memory below
	 * topOfKernelData, and publish its range in /chosen/memory-map.  XNU's
	 * load_static_trust_cache() reads exactly that property; without it
	 * AMFI rejects every platform binary (launchd included).
	 */
	if (dtsize) {
		if (load_trust_cache(root, img, rd_len != 0,
		    &tc_phys, &tc_len) == 0) {
			u64 range[2];

			range[0] = tc_phys;
			range[1] = tc_len;
			if (gh_adt_add_property((u8 *)dt_phys, GH_DT_MAX,
			    "chosen/memory-map", "TrustCache", range,
			    sizeof(range), &dtsize) == 0) {
				gh_loghex("memory-map      : TrustCache ", tc_phys);
				gh_loghex("memory-map      : length ", tc_len);
			} else {
				gh_log("memory-map      : could not publish TrustCache\n");
			}
		}

		/*
		 * A restore ramdisk is handed over the same way: a { paddr,
		 * length } pair that IOKitBSDInit turns into /dev/md0 before
		 * the root device is picked.
		 */
		if (rd_len) {
			u64 range[2];

			range[0] = img + rd_off;
			range[1] = rd_len;
			if (gh_adt_add_property((u8 *)dt_phys, GH_DT_MAX,
			    "chosen/memory-map", "RAMDisk", range,
			    sizeof(range), &dtsize) == 0) {
				gh_loghex("memory-map      : RAMDisk ", range[0]);
				gh_loghex("memory-map      : length ", rd_len);
			} else {
				gh_log("memory-map      : could not publish RAMDisk\n");
			}
		}
	}

	/*
	 * The tree is a template.  The machine's DRAM window, the panic
	 * region's address and the SoC window that ends where RAM begins all
	 * depend on the firmware map and on where the image landed, so patch
	 * them here, before XNU sees the tree.  Every edit is in place: no
	 * property grows or shrinks, so boot_args->deviceTreeP stays valid.
	 */
	if (dtsize) {
		u64 dram[2];
		u64 pram[2];
		u8 ranges[24];
		const u8 *old = 0;
		u32 old_len = 0;

		dram[0] = gh_memory_base();
		dram[1] = gh_memory_size();
		pram[0] = img + panic_off;
		pram[1] = GH_PANIC_SIZE;

		if (gh_adt_set_property((u8 *)dt_phys, GH_DT_MAX, "chosen",
		    "dram-base", &dram[0], sizeof(dram[0]), &dtsize) != 0 ||
		    gh_adt_set_property((u8 *)dt_phys, GH_DT_MAX, "chosen",
		    "dram-size", &dram[1], sizeof(dram[1]), &dtsize) != 0)
			gh_log("device tree     : could not set the dram window\n");

		if (gh_adt_set_property((u8 *)dt_phys, GH_DT_MAX, "pram",
		    "reg", pram, sizeof(pram), &dtsize) != 0)
			gh_log("device tree     : could not set the panic region\n");

		/*
		 * /arm-io "ranges" is { child 0, SoC base, window size }: the
		 * device window runs from the SoC base to the start of RAM.
		 * XNU resolves every arm-io child's reg through it, so a
		 * machine whose RAM begins somewhere else needs it to match.
		 */
		if (gh_adt_get_property((const u8 *)dt_phys, dtsize, "arm-io",
		    "ranges", &old, &old_len) == 0 &&
		    old_len == sizeof(ranges)) {
			u64 soc;

			gh_memcpy(ranges, old, sizeof(ranges));
			soc = rd64le(ranges + 8);
			if (gh_memory_base() > soc) {
				wr64le(ranges + 16,
				    gh_memory_base() - soc);
				if (gh_adt_set_property((u8 *)dt_phys,
				    GH_DT_MAX, "arm-io", "ranges", ranges,
				    sizeof(ranges), &dtsize) != 0)
					gh_log("device tree     : could not set "
					    "the arm-io window\n");
			}
		}

		gh_loghex("dram base       : ", dram[0]);
		gh_loghex("dram size       : ", dram[1]);

		/*
		 * With the tree final, take Lantern's windows, interrupts and
		 * GIC distributor from it.  Stage 2 runs after this and maps
		 * exactly what the machine description says.
		 */
		gh_lantern_configure_adt((const u8 *)dt_phys, dtsize);
	}

	/* boot args */
	ba_phys = img + ba_off;
	{
		/*
		 * The boot_args window starts at the bottom of the boot data,
		 * not at the kernel: start.s moves both bases up to the mach
		 * header before it builds the bootstrap mapping, so the kernel's
		 * own addresses are unaffected, while the trust cache -- which
		 * arm_vm_prot_init() only accepts below segLOWEST -- is inside
		 * the physical aperture it maps.
		 */
		u64 win_base = tc_len ? tc_phys : img;
		u64 win_virt = m.link_base - (img - win_base);
		/*
		 * deviceTreeP is a *virtual* address, as it is on Apple
		 * hardware: XNU dereferences it directly once its bootstrap
		 * KVA mapping is live, and SecureDTIsLockedDown() decides
		 * whether the tree sits in front of the kernel by comparing
		 * kvtophys(deviceTreeP) against kvtophys(&_mh_execute_header).
		 * Handing over a physical address there makes that comparison
		 * meaningless (it reads as "locked down", which puts the tree
		 * in EXTRADATA, and then requires the trust cache to sit
		 * immediately after it).
		 */
		u64 dt_va = win_virt + (dt_phys - win_base);
		/*
		 * topOfKernelData must cover every byte of boot data: the
		 * kernel maps [end_kern, topOfKernelData) read-write, slides
		 * the device tree inside it (PE_slide_devicetree) and then
		 * hands everything from topOfKernelData up to the VM layer as
		 * free memory.
		 *
		 * It must also sit at least one L2 block length ("twig") above
		 * physBase.  arm_vm_physmap_init() packs the physical aperture
		 * into the separate physmap window as a list of slices whose
		 * virtual addresses are block-aligned one after another, and its
		 * final check
		 *
		 *   assert((temp_ptov_table[ptov_index-1].va +
		 *           temp_ptov_table[ptov_index-1].len) <= physmap_end)
		 *
		 * works out to "adj0 + L0 + ((D - L0) % TWIG) - D <= 0", where
		 * D is topOfKernelData - physBase, L0 is the boot data below
		 * the kernel (segLOWEST - virtBase) and adj0 is the
		 * block-alignment shift of the window (0..TWIG-1).  Since
		 * D - L0 is topOfKernelData - img, i.e. the 88 MiB from
		 * GH_PANIC_OFF, the inequality holds whatever the window base
		 * is; with no trust cache it degenerates to D >= TWIG.
		 */
		u64 top_of_boot = img + top_off;
		/*
		 * A rooted ramdisk has no other way in: it is the restore
		 * environment, it keeps /etc and /var on itself, and launchd's
		 * single-user shell on /dev/console is what puts us at a
		 * prompt.  An init override that also names an argument needs
		 * RB_SINGLE for the same reason: it is the only thing that
		 * makes XNU pass a second argv entry to PID 1.  Both belong to
		 * the handover, so an ordinary boot leaves GH_CMD_LINE alone.
		 */
		/*
		 * Bring-up handover: an optional one-line file on the ESP
		 * with extra kernel boot arguments (ignition level, dyld
		 * switches).  Absent by default, so an ordinary boot keeps
		 * GH_CMD_LINE exactly as shipped; present only while a
		 * diagnostic run needs a knob without rebuilding Gatehouse.
		 */
		char extra[160];
		extra[0] = 0;
		{
			u64 bsize = 0;
			u8 *bfile = read_file_opt(root,
			    L"\\gatehouse\\bootargs", &bsize, 1);

			if (bfile) {
				u64 k = 0;

				while (k < bsize && (bfile[k] == ' ' ||
				    bfile[k] == '\t')) {
					k++;
				}
				while (k < bsize && bfile[k] != '\n' &&
				    bfile[k] != '\r' &&
				    k < sizeof(extra) - 1) {
					extra[k] = bfile[k];
					k++;
				}
				extra[k] = 0;
				if (extra[0]) {
					gh_log("boot args extra : ");
					gh_log(extra);
					nl();
				}
			}
		}
		char cmdline[sizeof(GH_CMD_LINE) + 176];
		const char *suffix = "";
		u64 ci, cn = 0;
		int sz;

		for (ci = 0; GH_CMD_LINE[ci]; ci++) {
			cmdline[cn++] = GH_CMD_LINE[ci];
		}

		/*
		 * cpus=N, read back out of the tree's own /cpus count.  The
		 * machine description is the one place the number is chosen,
		 * so the boot arg and the hardware stay in step by
		 * construction; ml_parse_cpu_topology() takes the first N
		 * /cpus children.  A tree with no (or an unparseable) /cpus
		 * stays single-CPU, which is what the bring-up machine ran
		 * before the count was published.
		 */
		{
			int ncpu = dtsize ?
			    gh_adt_count_children((const u8 *)dt_phys, dtsize,
			        "cpus") : -1;
			char digits[4];
			int nd = 0;

			if (ncpu < 1)
				ncpu = 1;
			cmdline[cn++] = ' ';
			cmdline[cn++] = 'c';
			cmdline[cn++] = 'p';
			cmdline[cn++] = 'u';
			cmdline[cn++] = 's';
			cmdline[cn++] = '=';
			do {
				digits[nd++] = (char)('0' + ncpu % 10);
				ncpu /= 10;
			} while (ncpu && nd < (int)sizeof(digits));
			while (nd > 0)
				cmdline[cn++] = digits[--nd];
		}

		if (rd_len) {
			suffix = " rd=md0 -s";
		} else if (init_arg) {
			suffix = " -s";
		}
		for (ci = 0; suffix[ci]; ci++) {
			cmdline[cn++] = suffix[ci];
		}
		if (extra[0]) {
			cmdline[cn++] = ' ';
			for (ci = 0; extra[ci]; ci++) {
				cmdline[cn++] = extra[ci];
			}
		}
		cmdline[cn] = 0;

		/* The panic region the ADT advertises must be where the image
		 * landed, must not collide with the image, device tree,
		 * boot_args or trust cache, and must stay inside
		 * topOfKernelData. */
		if (img + panic_off < img + boot_off ||
		    (tc_len && img + panic_off < tc_phys + tc_len) ||
		    img + panic_off + GH_PANIC_SIZE > top_of_boot) {
			gh_uart_puts("bad panic region placement\n");
			return 1;
		}
		gh_loghex("panic region    : ", img + panic_off);

		gh_loghex("kernel window   : ", win_base);
		gh_loghex("kernel window VA: ", win_virt);
		gh_loghex("device tree VA  : ", dt_va);
		sz = gh_bootargs_build((void *)ba_phys, win_virt, win_base,
		    gh_memory_top() - win_base, top_of_boot, dt_va,
		    (u32)dtsize, cmdline);
		gh_uart_puts("boot_args size  : ");
		gh_uart_putdec((u64)sz);
		nl();
	}

	p = (u8 *)ba_phys;
	(void)p;
	gh_loghex("boot_args phys  : ", ba_phys);
	gh_loghex("jump entry (PA) : ", img + (m.entry - m.link_base));

	/* The image must be fetchable before we branch into it. */
	make_range_executable(img, alloc_sz);

#ifdef GH_ATTACH_STALL_MS
	if (BS->Stall) {
		puts_("waiting for debugger attach...\n");
		BS->Stall(GH_ATTACH_STALL_MS * 1000);
	}
#endif

	puts_("\n== transferring control to XNU ==\n\n");

	gh_jump_to_kernel(img + (m.entry - m.link_base), ba_phys,
	    img + top_off - 0x100, /* provisional stack; kernel uses its own */
	    img, alloc_sz);        /* region to flush before dropping the MMU */
	return 0;
}

/* ------------------------------------------------------------------ */

unsigned long long efi_main(void *image_handle, EFI_SYSTEM_TABLE *st)
{
	(void)image_handle;
	ST = st;
	BS = st->BootServices;

	gh_uart_init();
	banner();
	dump_config_tables();

	load_and_jump();

	/* If we ever get here the jump did not happen. */
	puts_("\nGatehouse: returned / halted.\n");
	for (;;) {
	}
}
