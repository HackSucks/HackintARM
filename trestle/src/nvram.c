// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/nvram.c - the NVRAM device model (see include/nvram.h).
#include "nvram.h"

// ---------------------------------------------------------------------------
// Minimal freestanding helpers.  Trestle does not link a C library.
// ---------------------------------------------------------------------------
static void nv_memset(void *dst, int c, usize n)
{
    u8 *d = (u8 *)dst;
    while (n--) {
        *d++ = (u8)c;
    }
}

static void store_u32(u8 *p, u32 v)
{
    p[0] = (u8)(v & 0xff);
    p[1] = (u8)((v >> 8) & 0xff);
    p[2] = (u8)((v >> 16) & 0xff);
    p[3] = (u8)((v >> 24) & 0xff);
}

static u32 load_u32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

// ---------------------------------------------------------------------------
// Image construction.
// ---------------------------------------------------------------------------
int trestle_nvram_is_valid(const u8 *image, usize size)
{
    if (image == 0 || size < NVRAM_V3_HEADER_SIZE) {
        return 0;
    }
    if (load_u32(image) != NVRAM_V3_MAGIC) {
        return 0;
    }
    if (load_u32(image + 4) != (u32)size) {
        return 0;
    }
    return image[0xe] == NVRAM_V3_VERSION;
}

nvram_v3_header *trestle_nvram_format(u8 *storage, usize size)
{
    nvram_v3_header *hdr;

    if (storage == 0 || size < NVRAM_V3_HEADER_SIZE || size > NVRAM_MAX_SIZE) {
        return 0;
    }

    nv_memset(storage, 0, size);
    hdr = (nvram_v3_header *)storage;
    store_u32(storage + 0x00, NVRAM_V3_MAGIC);
    store_u32(storage + 0x04, (u32)size);
    store_u32(storage + 0x08, 0);               // region offset
    storage[0x0e] = NVRAM_V3_VERSION;
    store_u32(storage + 0x10, 0);               // field_10
    store_u32(storage + 0x14, (u32)size);       // data_end
    return hdr;
}

trestle_status trestle_nvram_init(trestle_nvram *nv, u8 *storage, usize size)
{
    if (nv == 0 || storage == 0) {
        return TRESTLE_ERR_INVAL;
    }
    if (size == 0) {
        size = NVRAM_DEFAULT_SIZE;
    }
    if (size < NVRAM_V3_HEADER_SIZE || size > NVRAM_MAX_SIZE) {
        return TRESTLE_ERR_INVAL;
    }

    nv->image = storage;
    nv->size = size;
    nv->generation = 0;
    nv->dirty = 0;
    nv->raw = 0;

    // Keep an already-valid store (it may hold live variables); otherwise
    // format a fresh, factory-empty image.
    if (!trestle_nvram_is_valid(storage, size)) {
        if (trestle_nvram_format(storage, size) == 0) {
            return TRESTLE_ERR_INVAL;
        }
    }
    nv->header = (nvram_v3_header *)storage;
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// Device-model entry point.
// ---------------------------------------------------------------------------
trestle_status trestle_nvram_contribute(trestle_device *dev, void *node)
{
    trestle_nvram *nv = (trestle_nvram *)dev;

    // The device-tree builder is not yet a Trestle component: on the QEMU
    // bring-up the platform description is produced by
    // gatehouse/dt/build_adt.py, which mirrors this model.  When Trestle owns
    // the tree, this emits, on /chosen:
    //
    //     nvram-total-size = <nv->size>
    //     nvram-bank-size  = <nv->size>
    //     nvram-bank-count = <1>
    //     nvram-current-bank = <0>
    //     nvram-raw        = <nv->raw>
    //     nvram-proxy-data = <nv->image, nv->size>
    //
    // See docs/design.md ("Device tree ownership").
    TRESTLE_UNUSED(node);
    if (nv == 0) {
        return TRESTLE_ERR_INVAL;
    }
    return TRESTLE_ERR_NOTSUP;
}
