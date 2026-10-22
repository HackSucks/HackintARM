// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/include/gh.h - Gatehouse bootloader internal API.
 *
 * Gatehouse is the HackintARM ARM64 bootloader. It runs as a UEFI
 * application on QEMU `virt`, but contains no platform-specific crutches:
 * everything it does to XNU it would also do on a real SoC.
 */
#ifndef GATEHOUSE_GH_H
#define GATEHOUSE_GH_H

#include "efi.h"

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef signed long long    i64;

/* uart.c */
void gh_uart_init(void);
void gh_uart_putc(char c);
void gh_uart_puts(const char *s);
void gh_uart_puthex(u64 v);
void gh_uart_putdec(u64 v);

/* lib.c */
void *gh_memset(void *d, int c, u64 n);
void *gh_memcpy(void *d, const void *s, u64 n);
int   gh_memcmp(const void *a, const void *b, u64 n);
u64   gh_strlen(const char *s);
void  gh_log(const char *s);
void  gh_loghex(const char *tag, u64 v);

/* macho.c */
#define GH_MAX_SEGS 32
typedef struct {
	u64 vmaddr;
	u64 vmsize;
	u64 fileoff;
	u64 filesize;
	u32 maxprot;
	u32 initprot;
	char segname[17];
	char first_sect[17];
	int is_zerofill;   /* first section is __bss-like (filesize == 0) */
} gh_segment;

typedef struct {
	u64 entry;         /* entry point virtual address */
	u64 link_base;     /* vmaddr of the segment containing the mach header */
	u64 text_size;     /* total span covered by segments */
	u32 nsegs;
	u32 cputype;
	u32 cpusubtype;
	u32 filetype;
	u32 flags;
	/*
	 * MH_FILESET (a kernel collection) is loaded differently from an
	 * ordinary kernel: the file is a flat 1:1 image of the VA window, its
	 * chained fixups are applied by XNU itself (arm_slide_rebase_and_sign_
	 * image -> kernel_collection_slide), and the entry point lives in the
	 * *collection's* LC_UNIXTHREAD, not in the kernel slice's.
	 */
	u32 is_fileset;
	u32 nfileset;            /* LC_FILESET_ENTRY count (0 if not a fileset) */
	u64 kslice_vmaddr;       /* com.apple.kernel slice vmaddr (0 if absent)  */
	gh_segment segs[GH_MAX_SEGS];
	const u8 *file;
	u64 filesize;
} gh_macho;

int gh_macho_parse(gh_macho *m, const u8 *base, u64 size);
/* Copy a parsed Mach-O into memory at `phys_dest` (identity/V=P image). */
int gh_macho_load_flat(const gh_macho *m, u64 phys_dest, u64 *out_top);

/*
 * fixups.c - load completion.  Resolves the LC_DYLD_CHAINED_FIXUPS the image
 * declares, i.e. the relocation step iBoot/dyld would perform, so the kernel
 * sees real pointers.  Returns the number of slots rewritten (0 if the image
 * carries no chains, as a kernel collection would not).
 */
int gh_apply_fixups(const gh_macho *m, u8 *img);

/*
 * patch.c - load-time fixups, applied to the flattened image in memory.
 * `m` is the parsed image: the patches decode pc-relative operands to find
 * the code they edit, which needs the segment table to turn a file offset
 * into the address the instruction will run at.
 */
int gh_patch_kernel(u8 *img, u64 span, const gh_macho *m);

/*
 * Point XNU's PID 1 at another program (Linux's init=, for bring-up).  The
 * path must be absolute and no longer than the shipped one; a machine with a
 * complete root volume runs it as-is, one without gets a shell.
 */
int gh_patch_init_program(u8 *img, u64 span, const gh_macho *m,
    const char *path);

/*
 * Choose PID 1's single argument.  XNU ships "-s"; a rescue shell wants a
 * path there instead, so that the shell opens the console itself.  The string
 * is written to `arg_off`, an image-relative offset in the loaded window
 * (outside the image, inside `win`), because the image has no suitable
 * NUL-terminated one of its own.  Only meaningful when the command line sets
 * RB_SINGLE ("-s").
 */
int gh_patch_init_argument(u8 *img, u64 span, u64 win, const gh_macho *m,
    const char *arg, u64 arg_off);

/* bootargs.c */
int gh_bootargs_build(void *dst, u64 virt_base, u64 phys_base, u64 mem_size,
    u64 top_of_kernel_data, u64 dt_phys, u32 dt_len, const char *cmdline);

/*
 * adt.c - edit the device tree in memory.  iBoot fills /chosen/memory-map in
 * as it loads each boot object, so a loader has to be able to append
 * properties to a node; `size` is the tree's length in and out and `cap`
 * bounds the buffer it lives in.
 */
int gh_adt_add_property(u8 *dt, u64 cap, const char *path, const char *name,
    const void *value, u32 len, u64 *size);

/* jump.S */
void gh_jump_to_kernel(u64 entry, u64 bootargs_pa, u64 stack_top,
    u64 clean_base, u64 clean_len) __attribute__((noreturn));

#endif /* GATEHOUSE_GH_H */
