// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/tests/nvram_test.c - host-side checks for the NVRAM device model.
//
// Builds against the host libc (nvram.c itself is freestanding) and asserts
// the image the model produces is exactly what XNU's IONVRAMV3Handler expects:
// the store magic, the size echoed in the header, version 1 at 0x0e, and a
// size that agrees with what the handler is created with.
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../include/nvram.h"

static u32 rd32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

int main(void)
{
    static u8     storage[NVRAM_DEFAULT_SIZE];
    trestle_nvram nv;

    assert(trestle_nvram_init(&nv, storage, sizeof(storage)) == TRESTLE_OK);
    assert(nv.size == NVRAM_DEFAULT_SIZE);
    assert(trestle_nvram_is_valid(storage, sizeof(storage)));

    // The four things the factory and the V3 parser check.
    assert(rd32(storage + 0x00) == NVRAM_V3_MAGIC);
    assert(rd32(storage + 0x04) == NVRAM_DEFAULT_SIZE);
    assert(storage[0x0e] == NVRAM_V3_VERSION);
    assert(sizeof(nvram_v3_header) == NVRAM_V3_HEADER_SIZE);

    // Re-initialising must not clobber a valid store.
    storage[0x40] = 0xAB;
    assert(trestle_nvram_init(&nv, storage, sizeof(storage)) == TRESTLE_OK);
    assert(storage[0x40] == 0xAB);

    // A wrong magic or size is rejected.
    storage[0] = 0;
    assert(!trestle_nvram_is_valid(storage, sizeof(storage)));
    assert(trestle_nvram_format(storage, sizeof(storage)) != 0);
    assert(trestle_nvram_is_valid(storage, sizeof(storage)));
    assert(!trestle_nvram_is_valid(storage, sizeof(storage) - 4));

    // Too small to hold a header.
    assert(trestle_nvram_init(&nv, storage, 0x10) == TRESTLE_ERR_INVAL);

    printf("nvram_test: OK (size=%u magic=%#x version=%u)\n", (unsigned)nv.size,
           rd32(storage + 0x00), storage[0x0e]);
    return 0;
}
