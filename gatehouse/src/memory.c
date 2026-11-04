// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/src/memory.c - what RAM the machine actually has.
 *
 * Nothing above this file may assume a RAM base or size.  The firmware
 * memory map is the authority: it describes the machine Gatehouse is running
 * on, whether that is QEMU's virt board with -m 3G, a phone, a laptop or a
 * server.  Gatehouse asks for the largest contiguous run of memory the OS may
 * use and reports that range to XNU (boot_args and /chosen dram-base/
 * dram-size) and to Trestle (the stage-2 map).
 *
 * XNU on Apple Silicon takes one contiguous DRAM window from
 * /chosen/dram-base and dram-size, so a single run is the right contract.
 * Machines with discontiguous RAM are described by their largest run; the
 * others are logged rather than silently folded into one window, which would
 * claim that a hole is memory.
 *
 * The map's EfiMemoryMappedIO ranges are devices, not RAM: including them
 * would make the guest cacheable-map MMIO and miss the missing-hardware
 * faults that stage 2 exists to expose.  Unusable memory is excluded for the
 * same reason, and reserved memory because the firmware still owns it.
 */
#include "gh.h"

/* UEFI descriptors count 4 KiB pages whatever the CPU's translation granule. */
#define GH_EFI_PAGE_SIZE 0x1000ULL

/* Enough for any firmware map this loader has to walk.  If a map is larger,
 * the extra descriptors are dropped and the log says so. */
#define GH_RAM_RUNS 512

struct gh_run {
	u64 lo;
	u64 hi;
};

static struct gh_run gh_runs[GH_RAM_RUNS];
static u64 gh_ram_base;
static u64 gh_ram_top;

static int gh_memory_usable(u32 type)
{
	switch (type) {
	case EfiLoaderCode:
	case EfiLoaderData:
	case EfiBootServicesCode:
	case EfiBootServicesData:
	case EfiRuntimeServicesCode:
	case EfiRuntimeServicesData:
	case EfiConventionalMemory:
	case EfiACPIReclaimMemory:
	case EfiACPIMemoryNVS:
	case EfiPersistentMemory:
		return 1;
	default:
		return 0;
	}
}

/*
 * Merge overlapping/adjacent usable descriptors into runs and keep the
 * largest.  The map is normally sorted already; sorting here costs nothing
 * and makes the result independent of the firmware's ordering.
 */
static void gh_memory_merge(u32 n)
{
	u32 i, j, out = 0;
	u64 best = 0;

	for (i = 1; i < n; i++) {
		struct gh_run r = gh_runs[i];

		for (j = i; j > 0 && gh_runs[j - 1].lo > r.lo; j--)
			gh_runs[j] = gh_runs[j - 1];
		gh_runs[j] = r;
	}

	for (i = 0; i < n; i++) {
		if (out && gh_runs[i].lo <= gh_runs[out - 1].hi) {
			if (gh_runs[i].hi > gh_runs[out - 1].hi)
				gh_runs[out - 1].hi = gh_runs[i].hi;
			continue;
		}
		gh_runs[out++] = gh_runs[i];
	}

	gh_ram_base = 0;
	gh_ram_top = 0;
	for (i = 0; i < out; i++) {
		u64 len = gh_runs[i].hi - gh_runs[i].lo;

		if (len > best) {
			best = len;
			gh_ram_base = gh_runs[i].lo;
			gh_ram_top = gh_runs[i].hi;
		}
	}

	if (out > 1) {
		gh_uart_puts("memory          : ");
		gh_uart_putdec(out);
		gh_uart_puts(" usable runs, using the largest\n");
	}
}

int gh_memory_discover(EFI_BOOT_SERVICES *bs)
{
	UINTN map_sz = 0, key_sz = 0, desc_sz = 0;
	UINT32 desc_ver = 0;
	EFI_MEMORY_DESCRIPTOR *map = 0, *d;
	EFI_STATUS s;
	u32 n = 0, total = 0;
	int dropped = 0;

	s = bs->GetMemoryMap(&map_sz, 0, &key_sz, &desc_sz, &desc_ver);
	if (s != EFI_BUFFER_TOO_SMALL || desc_sz == 0) {
		gh_loghex("memory          : GetMemoryMap(size) failed ", s);
		return -1;
	}
	map_sz += 16 * desc_sz;
	s = bs->AllocatePool(EfiLoaderData, map_sz, (void **)&map);
	if (EFI_ERROR(s)) {
		gh_loghex("memory          : AllocatePool failed ", s);
		return -1;
	}
	s = bs->GetMemoryMap(&map_sz, map, &key_sz, &desc_sz, &desc_ver);
	if (EFI_ERROR(s)) {
		gh_loghex("memory          : GetMemoryMap failed ", s);
		bs->FreePool(map);
		return -1;
	}

	for (d = map; (u8 *)d < (u8 *)map + map_sz;
	    d = (EFI_MEMORY_DESCRIPTOR *)((u8 *)d + desc_sz)) {
		u64 lo = d->PhysicalStart;
		u64 hi = lo + d->NumberOfPages * GH_EFI_PAGE_SIZE;

		total++;
		if (!gh_memory_usable(d->Type) || hi <= lo)
			continue;
		if (n == GH_RAM_RUNS) {
			dropped = 1;
			continue;
		}
		gh_runs[n].lo = lo;
		gh_runs[n].hi = hi;
		n++;
	}
	bs->FreePool(map);

	if (!n) {
		gh_log("memory          : no usable RAM in the firmware map\n");
		return -1;
	}
	if (dropped) {
		gh_log("memory          : map too large, extra descriptors ignored\n");
	}

	gh_memory_merge(n);

	gh_uart_puts("memory          : ");
	gh_uart_putdec(total);
	gh_uart_puts(" descriptors, ");
	gh_uart_putdec(n);
	gh_uart_puts(" usable\n");

	/*
	 * XNU's 16 KiB granule means dram-base has to be 16 KiB aligned: it
	 * seeds pmap_first_pnum with dram-base >> 14, and every physical page
	 * in the window is then assumed to start on a page boundary.  UEFI
	 * descriptors are 4 KiB, so a run can begin mid-page; trim rather than
	 * claim the fragment.
	 */
	gh_ram_base = (gh_ram_base + GH_PAGE - 1) & ~(GH_PAGE - 1);
	gh_ram_top &= ~(GH_PAGE - 1);
	if (!gh_ram_base || gh_ram_top <= gh_ram_base) {
		gh_log("memory          : no usable RAM run found\n");
		return -1;
	}
	if (gh_ram_top > (1ULL << 39)) {
		/*
		 * The stage-2 map is a 39-bit IPA (512 GiB), which covers every
		 * Apple Silicon part and every board this loader targets.  A
		 * larger machine needs a 40-bit IPA and an L0 table; until
		 * then, say so instead of handing XNU memory it cannot map.
		 */
		gh_log("memory          : RAM above 512 GiB, clamping the window\n");
		gh_ram_top = 1ULL << 39;
	}
	return 0;
}

u64 gh_memory_base(void)
{
	return gh_ram_base;
}

u64 gh_memory_top(void)
{
	return gh_ram_top;
}

u64 gh_memory_size(void)
{
	return gh_ram_top - gh_ram_base;
}
