// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/bootargs.c - construct the XNU `boot_args` structure.
 *
 * Layout mirrors pexpert/pexpert/arm64/boot.h. BOOT_LINE_LENGTH is
 * IBOOT_MAX_ENV_VAR_DATA_SIZE; the fields after CommandLine (bootFlags,
 * memSizeActual) only line up if this constant is right, so it is verified
 * against the target kernel at runtime once symbols are available.
 */
#include "gh.h"

#ifndef GH_BOOT_LINE_LENGTH
#define GH_BOOT_LINE_LENGTH 1024
#endif

#define kBootArgsRevision2 2
#define kBootArgsVersion2  2

typedef struct {
	u64 v_baseAddr;
	u64 v_display;
	u64 v_rowBytes;
	u64 v_width;
	u64 v_height;
	u64 v_depth;
} Boot_Video;

typedef struct {
	u16 Revision;
	u16 Version;
	u32 _pad;
	u64 virtBase;
	u64 physBase;
	u64 memSize;
	u64 topOfKernelData;
	Boot_Video Video;
	u32 machineType;
	u32 _pad2;              /* align deviceTreeP to 8; also in XNU */
	void *deviceTreeP;
	u32 deviceTreeLength;
	/*
	 * NO padding here: in XNU's arm64 struct boot_args the char array
	 * CommandLine follows deviceTreeLength immediately, so CommandLine is
	 * at offset 0x6c.  PE_parse_boot_argn() reads bootArgs + 0x6c (verified
	 * in the target kernel: _PE_parse_boot_argn does `add x0, x8, #0x6c`),
	 * and anything else makes the kernel see an empty command line.
	 */
	char CommandLine[GH_BOOT_LINE_LENGTH];
	u64 bootFlags;          /* compiler pads to here (0x470) */
	u64 memSizeActual;
} gh_boot_args;

/* The kernel hard-codes these offsets; fail the build if they drift. */
typedef char gh_assert_cmdline_off[
	(__builtin_offsetof(gh_boot_args, CommandLine) == 0x6c) ? 1 : -1];
typedef char gh_assert_bootflags_off[
	(__builtin_offsetof(gh_boot_args, bootFlags) == 0x470) ? 1 : -1];
typedef char gh_assert_size[
	(sizeof(gh_boot_args) == 0x480) ? 1 : -1];

int gh_bootargs_build(void *dst, u64 virt_base, u64 phys_base, u64 mem_size,
    u64 top_of_kernel_data, u64 dt_phys, u32 dt_len, const char *cmdline)
{
	gh_boot_args *b = (gh_boot_args *)dst;
	u64 i, n;

	gh_memset(b, 0, sizeof(*b));
	b->Revision = kBootArgsRevision2;
	b->Version = kBootArgsVersion2;
	b->virtBase = virt_base;
	b->physBase = phys_base;
	b->memSize = mem_size;
	b->topOfKernelData = top_of_kernel_data;
	b->machineType = 0;
	b->deviceTreeP = (void *)dt_phys;
	b->deviceTreeLength = dt_len;
	b->bootFlags = 0;
	b->memSizeActual = mem_size;

	n = gh_strlen(cmdline);
	if (n >= GH_BOOT_LINE_LENGTH) {
		n = GH_BOOT_LINE_LENGTH - 1;
	}
	for (i = 0; i < n; i++) {
		b->CommandLine[i] = cmdline[i];
	}
	b->CommandLine[n] = 0;

	return (int)sizeof(gh_boot_args);
}
