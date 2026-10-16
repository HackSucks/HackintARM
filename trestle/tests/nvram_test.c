// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/tests/nvram_test.c - host-side checks for the NVRAM device model.
//
// Builds against the host libc (nvram.c itself is freestanding) and asserts
// the CHRP image the model produces is exactly what XNU's IONVRAMCHRPHandler
// expects to find: 16-byte-aligned partitions whose header bytes sum to zero
// and which include a "system" and a "common" partition.
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../include/nvram.h"

static const u8 *find_partition(const u8 *image, usize size, const char *name,
                                const u8 **data, usize *data_len)
{
    usize off = 0;
    while (off + sizeof(nvram_chrp_header) <= size) {
        const nvram_chrp_header *hdr = (const nvram_chrp_header *)(image + off);
        usize len = (usize)hdr->len * NVRAM_CHRP_BLOCK;
        if (len < sizeof(*hdr) || off + len > size) {
            break;
        }
        if (strncmp(hdr->name, name, strlen(name)) == 0) {
            *data = image + off + sizeof(*hdr);
            *data_len = len - sizeof(*hdr);
            return image + off;
        }
        off += len;
    }
    return 0;
}

static void check_header_sums_to_zero(const u8 *part)
{
    unsigned sum = 0;
    for (int i = 0; i < (int)sizeof(nvram_chrp_header); i++) {
        sum += part[i];
    }
    assert((sum & 0xFF) == 0);
}

int main(void)
{
    static u8     storage[NVRAM_DEFAULT_SIZE];
    trestle_nvram nv;
    const u8     *sys, *com, *data;
    usize         data_len;

    assert(trestle_nvram_init(&nv, storage, sizeof(storage)) == TRESTLE_OK);
    assert(nv.size == NVRAM_DEFAULT_SIZE);

    sys = find_partition(storage, sizeof(storage), "system", &data, &data_len);
    com = find_partition(storage, sizeof(storage), "common", &data, &data_len);
    assert(sys != 0);
    assert(com != 0);

    check_header_sums_to_zero(sys);
    check_header_sums_to_zero(com);

    assert(((const nvram_chrp_header *)sys)->sig == NVRAM_CHRP_SIG_SYSTEM);
    assert(((const nvram_chrp_header *)com)->sig == NVRAM_CHRP_SIG_CONFIG);

    // The whole image is consumed by the two partitions.
    usize used = (usize)((const nvram_chrp_header *)sys)->len * NVRAM_CHRP_BLOCK;
    assert(sys + used == com);
    assert((usize)((const nvram_chrp_header *)com)->len * NVRAM_CHRP_BLOCK +
               (usize)(com - sys) ==
           NVRAM_DEFAULT_SIZE);

    // The parser records geometry for both partitions.
    assert(nv.system_partition_offset != 0xFFFFFFFFu);
    assert(nv.common_partition_offset != 0xFFFFFFFFu);
    assert(nv.common_partition_size > 0);

    printf("nvram_test: OK (size=%u system=%u common=%u)\n", (unsigned)nv.size,
           (unsigned)nv.system_partition_size, (unsigned)nv.common_partition_size);
    return 0;
}
