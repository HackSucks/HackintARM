// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/macho.c - Mach-O (arm64e) parser + flat V=P loader.
 *
 * We deliberately do not use any Mach-O library: this is the exact code that
 * will run on a real SoC, so it stays small and auditable.
 */
#include "gh.h"

#define MH_MAGIC_64   0xfeedfacf
#define CPU_TYPE_ARM64 0x0100000c
#define CPU_SUBTYPE_ARM64E 2

#define LC_SEGMENT_64    0x19
#define LC_UNIXTHREAD    0x05
#define LC_MAIN          0x80000028
#define LC_FILESET_ENTRY 0x80000035

#define MH_EXECUTE     0x2
#define MH_FILESET     12   /* kernel collection: a set of Mach-O slices */

#define VM_PROT_EXECUTE 0x4

typedef struct {
	u32 magic;
	u32 cputype;      /* cpu_type_t  - 32-bit */
	u32 cpusubtype;   /* cpu_subtype_t - 32-bit */
	u32 filetype;
	u32 ncmds;
	u32 sizeofcmds;
	u32 flags;
	u32 reserved;
} mach_header_64;

typedef struct {
	u32 cmd;
	u32 cmdsize;
	char segname[16];
	u64 vmaddr;
	u64 vmsize;
	u64 fileoff;
	u64 filesize;
	u32 maxprot;
	u32 initprot;
	u32 nsects;
	u32 flags;
} segment_command_64;

typedef struct {
	u32 cmd;
	u32 cmdsize;
	u64 entryoff;
	u64 stacksize;
} entry_point_command;

/*
 * LC_FILESET_ENTRY: one slice of an MH_FILESET kernel collection.  entry_id
 * is an lc_str, i.e. a byte offset *relative to the start of this command*.
 */
typedef struct {
	u32 cmd;
	u32 cmdsize;
	u64 vmaddr;
	u64 fileoff;
	u32 entry_id_off;
	u32 reserved;
} fileset_entry_command;

typedef struct {
	char sectname[16];
	char segname[16];
	u64 addr;
	u64 size;
	u32 offset;
	u32 align;
	u32 reloff;
	u32 nreloc;
	u32 flags;
	u32 reserved1;
	u32 reserved2;
	u32 reserved3;
} section_64;

#define S_ZEROFILL 0x1

static int name_eq(const char *a16, const char *b)
{
	int i;
	for (i = 0; i < 16; i++) {
		char ca = a16[i], cb = b[i];
		if (ca != cb) {
			return 0;
		}
		if (ca == 0) {
			return 1;
		}
	}
	return 1;
}

/* Compare a NUL-terminated string that lives inside the load-command area. */
static int id_eq(const u8 *s, const u8 *end, const char *want)
{
	while (s < end) {
		if (*want == 0) {
			return *s == 0;
		}
		if (*s != (u8)*want) {
			return 0;
		}
		s++;
		want++;
	}
	return 0;
}

int gh_macho_parse(gh_macho *m, const u8 *base, u64 size)
{
	const mach_header_64 *mh;
	const u8 *p, *end;
	u32 i;

	if (size < sizeof(mach_header_64)) {
		gh_log("macho: file too small\n");
		return -1;
	}
	gh_memset(m, 0, sizeof(*m));
	m->file = base;
	m->filesize = size;

	mh = (const mach_header_64 *)base;
	if (mh->magic != MH_MAGIC_64) {
		gh_loghex("macho: bad magic ", mh->magic);
		return -2;
	}
	m->cputype = (u32)mh->cputype;
	m->cpusubtype = (u32)mh->cpusubtype;
	m->filetype = mh->filetype;
	m->flags = mh->flags;
	if (m->cputype != CPU_TYPE_ARM64) {
		gh_loghex("macho: unexpected cputype ", m->cputype);
	}
	m->link_base = ~0ULL;

	p = base + sizeof(mach_header_64);
	end = p + mh->sizeofcmds;
	if (end > base + size) {
		gh_log("macho: load commands overflow file\n");
		return -3;
	}

	for (i = 0; i < mh->ncmds; i++) {
		const u32 cmd = *(const u32 *)p;
		const u32 cmdsize = *(const u32 *)(p + 4);
		if (cmdsize < 8 || p + cmdsize > end) {
			gh_log("macho: malformed load command\n");
			return -4;
		}
		if (cmd == LC_SEGMENT_64 && m->nsegs < GH_MAX_SEGS) {
			const segment_command_64 *sg = (const segment_command_64 *)p;
			gh_segment *s = &m->segs[m->nsegs];
			int j;
			gh_memset(s, 0, sizeof(*s));
			for (j = 0; j < 16; j++) {
				s->segname[j] = sg->segname[j];
			}
			s->segname[16] = 0;
			s->vmaddr = sg->vmaddr;
			s->vmsize = sg->vmsize;
			s->fileoff = sg->fileoff;
			s->filesize = sg->filesize;
			s->maxprot = sg->maxprot;
			s->initprot = sg->initprot;
			if (sg->nsects > 0) {
				const section_64 *sc = (const section_64 *)(p + sizeof(segment_command_64));
				for (j = 0; j < 16; j++) {
					s->first_sect[j] = sc->sectname[j];
				}
				s->first_sect[16] = 0;
			}
			/* The kernel base is the first file-backed segment
			 * (__TEXT, fileoff 0).  Do NOT use min(vmaddr): a KDK
			 * kernel carries empty __PRELINK_TEXT/__PLK_* segments
			 * parked at a much lower address. */
			if (m->link_base == ~0ULL && sg->fileoff == 0 && sg->vmsize != 0 &&
			    !name_eq(sg->segname, "__PAGEZERO")) {
				m->link_base = sg->vmaddr;
			}
			m->nsegs++;
		} else if (cmd == LC_MAIN) {
			const entry_point_command *ep = (const entry_point_command *)p;
			m->entry = ep->entryoff;   /* fixed up after link_base known */
		} else if (cmd == LC_UNIXTHREAD) {
			/* arm_thread_state64: x[29],fp,lr,sp,pc ; pc at state+256.
			 * [cmd:4][cmdsize:4][flavor:4][count:4][state...]
			 *
			 * For an MH_FILESET collection this is the authoritative
			 * entry point: the kernel slice carries its own
			 * LC_UNIXTHREAD, but its pc is expressed in the layout the
			 * slice had before the collection linker placed it (it
			 * does not point into the collection at all).  The pc in
			 * the collection header does, and XNU's own boot path
			 * (arm_slide_rebase_and_sign_image) reads exactly the
			 * collection header, so we follow it too. */
			const u8 *st = p + 16;
			if (cmdsize >= 16 + 264) {
				u64 pc = *(const u64 *)(st + 256);
				if (m->entry == 0) {
					m->entry = pc;
				}
			}
		} else if (cmd == LC_FILESET_ENTRY &&
		    cmdsize >= sizeof(fileset_entry_command)) {
			const fileset_entry_command *fe =
			    (const fileset_entry_command *)p;
			if ((const u8 *)p + fe->entry_id_off < end) {
				m->nfileset++;
				if (id_eq(p + fe->entry_id_off, end,
				    "com.apple.kernel")) {
					m->kslice_vmaddr = fe->vmaddr;
				}
			}
		}
		p += cmdsize;
	}

	if (m->nsegs == 0) {
		gh_log("macho: no segments\n");
		return -5;
	}
	if (m->link_base == ~0ULL) {
		/* fall back to the lowest non-empty segment */
		u32 k;
		m->link_base = ~0ULL;
		for (k = 0; k < m->nsegs; k++) {
			if (m->segs[k].vmsize && m->segs[k].vmaddr < m->link_base) {
				m->link_base = m->segs[k].vmaddr;
			}
		}
	}
	/* If link_base is still the first non-pagezero seg, LC_MAIN entryoff is
	 * relative to the text segment base. */
	{
		int i2;
		for (i2 = 0; i2 < (int)m->nsegs; i2++) {
			gh_segment *s = &m->segs[i2];
			u64 top = s->vmaddr + s->vmsize;
			if (top > m->text_size) {
				m->text_size = top;
			}
		}
	}
	m->text_size -= m->link_base;

	/*
	 * A kernel collection (MH_FILESET) is a flat 1:1 image of its whole
	 * virtual window: every segment satisfies "vmaddr - fileoff == link_
	 * base", the slices are packed into kind-grouped regions, and the file
	 * continues past the last top-level segment.  Load it verbatim, and let
	 * the span cover the entire file.
	 */
	if (m->filetype == MH_FILESET) {
		u32 k;

		m->is_fileset = 1;
		if (m->text_size < size) {
			m->text_size = size;
		}
		/* Every segment must agree with the 1:1 rule, or the verbatim
		 * copy would drop code at the wrong virtual address. */
		for (k = 0; k < m->nsegs; k++) {
			if (m->segs[k].vmsize &&
			    m->segs[k].vmaddr - m->segs[k].fileoff != m->link_base) {
				gh_loghex("macho: fileset segment not 1:1: ",
				    m->segs[k].vmaddr);
				return -6;
			}
		}
	}

	/* LC_MAIN entryoff fixup: entry is an offset into the text segment. */
	if (m->entry != 0 && m->entry < m->link_base) {
		m->entry = m->link_base + m->entry;
	}

	/* Whatever happens next, the entry has to land in executable code. */
	{
		u32 k;
		int ok = 0;

		for (k = 0; k < m->nsegs; k++) {
			if ((m->segs[k].initprot & VM_PROT_EXECUTE) &&
			    m->entry >= m->segs[k].vmaddr &&
			    m->entry < m->segs[k].vmaddr + m->segs[k].vmsize) {
				ok = 1;
			}
		}
		if (!ok) {
			gh_loghex("macho: entry outside executable segments: ",
			    m->entry);
		}
	}
	return 0;
}

int gh_macho_load_flat(const gh_macho *m, u64 phys_dest, u64 *out_top)
{
	u32 i;
	u64 top = 0;

	/*
	 * A kernel collection is a verbatim image of its VA window, including
	 * the parts no segment describes (inter-slice padding, code signature).
	 * Copying the file byte-for-byte is therefore not an optimisation but
	 * the only faithful thing to do -- XNU will rebase and sign the whole
	 * window in place from arm_init().
	 */
	if (m->is_fileset) {
		gh_memcpy((void *)phys_dest, m->file, m->filesize);
		if (out_top) {
			*out_top = phys_dest + m->filesize;
		}
		return 0;
	}

	for (i = 0; i < m->nsegs; i++) {
		const gh_segment *s = &m->segs[i];
		u64 dst, seg_top;

		if (name_eq(s->segname, "__PAGEZERO")) {
			continue;
		}
		if (s->vmaddr < m->link_base) {
			gh_loghex("macho: segment below link base: ", s->vmaddr);
			continue;
		}
		dst = phys_dest + (s->vmaddr - m->link_base);
		seg_top = dst + s->vmsize;

		if (s->filesize) {
			if (s->fileoff + s->filesize > m->filesize) {
				gh_log("macho: segment file range past EOF\n");
				return -1;
			}
			gh_memcpy((void *)dst, m->file + s->fileoff, s->filesize);
		}
		/* Zero the bss/zerofill tail (bounded to keep __PAGEZERO-class
		 * segments from exploding). */
		if (s->vmsize > s->filesize && (s->vmsize - s->filesize) < (512ULL << 20)) {
			gh_memset((void *)(dst + s->filesize), 0, s->vmsize - s->filesize);
		}
		if (seg_top > top) {
			top = seg_top;
		}
	}
	if (out_top) {
		*out_top = top;
	}
	return 0;
}
