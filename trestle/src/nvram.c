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

static void nv_memcpy(void *dst, const void *src, usize n)
{
    u8       *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    while (n--) {
        *d++ = *s++;
    }
}

static int nv_memcmp(const void *a, const void *b, usize n)
{
    const u8 *x = (const u8 *)a;
    const u8 *y = (const u8 *)b;
    while (n--) {
        if (*x != *y) {
            return (int)*x - (int)*y;
        }
        x++;
        y++;
    }
    return 0;
}

static usize align_up(usize v, usize a)
{
    return (v + (a - 1)) & ~(a - 1);
}

static int name_eq_12(const char *a, const char *b)
{
    char pad[NVRAM_CHRP_NAME_LEN];
    nv_memset(pad, 0, sizeof(pad));
    for (usize i = 0; i < NVRAM_CHRP_NAME_LEN && b[i]; i++) {
        pad[i] = b[i];
    }
    return nv_memcmp(a, pad, NVRAM_CHRP_NAME_LEN) == 0;
}

// ---------------------------------------------------------------------------
// CHRP image construction.
// ---------------------------------------------------------------------------
usize trestle_nvram_chrp_partition_size(usize data_size)
{
    return sizeof(nvram_chrp_header) + align_up(data_size, NVRAM_CHRP_BLOCK);
}

usize trestle_nvram_chrp_partition(u8 *out, usize out_size, u8 sig,
                                   const char *name, const void *data,
                                   usize data_size)
{
    nvram_chrp_header *hdr = (nvram_chrp_header *)out;
    usize              total = trestle_nvram_chrp_partition_size(data_size);
    u32                sum;

    if (total > out_size) {
        return 0;
    }

    nv_memset(out, 0, total);
    hdr->sig = sig;
    hdr->len = (u16)(total / NVRAM_CHRP_BLOCK);
    for (usize i = 0; i < NVRAM_CHRP_NAME_LEN && name[i]; i++) {
        hdr->name[i] = name[i];
    }
    if (data != 0 && data_size != 0) {
        nv_memcpy(out + sizeof(*hdr), data, data_size);
    }

    // cksum is chosen so the 16 header bytes sum to zero (mod 256).
    sum = 0;
    for (usize i = 0; i < sizeof(*hdr); i++) {
        sum += out[i];
    }
    hdr->cksum = (u8)(0u - sum);
    return total;
}

trestle_status trestle_nvram_parse(trestle_nvram *nv)
{
    usize offset = 0;

    nv->system_partition_offset = 0xFFFFFFFFu;
    nv->common_partition_offset = 0xFFFFFFFFu;

    while (offset + sizeof(nvram_chrp_header) <= nv->size) {
        const nvram_chrp_header *hdr = (const nvram_chrp_header *)(nv->image + offset);
        usize                    len = (usize)hdr->len * NVRAM_CHRP_BLOCK;
        usize                    data_off = offset + sizeof(*hdr);
        usize                    data_len;

        if (len < sizeof(*hdr) || data_off + (len - sizeof(*hdr)) > nv->size) {
            break;
        }
        data_len = len - sizeof(*hdr);

        if (name_eq_12(hdr->name, "system") || name_eq_12(hdr->name, "2system")) {
            nv->system_partition_offset = (u32)data_off;
            nv->system_partition_size = (u32)data_len;
        } else if (name_eq_12(hdr->name, "common") || name_eq_12(hdr->name, "2common")) {
            nv->common_partition_offset = (u32)data_off;
            nv->common_partition_size = (u32)data_len;
        }
        offset += len;
    }

    // A store with a common partition is the minimum XNU requires.
    return nv->common_partition_offset != 0xFFFFFFFFu
               ? TRESTLE_OK
               : TRESTLE_ERR_NOTFOUND;
}

trestle_status trestle_nvram_init(trestle_nvram *nv, u8 *storage, usize size)
{
    usize system_total;
    usize common_total;
    usize used;

    if (nv == 0 || storage == 0) {
        return TRESTLE_ERR_INVAL;
    }
    if (size == 0) {
        size = NVRAM_DEFAULT_SIZE;
    }
    if (size > NVRAM_MAX_SIZE || (size % NVRAM_CHRP_BLOCK) != 0) {
        return TRESTLE_ERR_INVAL;
    }

    nv->image = storage;
    nv->size = size;
    nv->generation = 0;
    nv->dirty = 0;
    nv_memset(storage, 0, size);

    // Split the image: a small "system" partition for the OS's own variables
    // and a "common" partition for everything else.  Both start empty; a
    // zeroed variable area deserialises to the factory dictionary.
    system_total = align_up(size / 8, NVRAM_CHRP_BLOCK);
    if (system_total < 2 * NVRAM_CHRP_BLOCK) {
        system_total = 2 * NVRAM_CHRP_BLOCK;
    }
    common_total = size - system_total;

    used = trestle_nvram_chrp_partition(storage, size, NVRAM_CHRP_SIG_SYSTEM,
                                        "system", 0,
                                        system_total - sizeof(nvram_chrp_header));
    if (used != system_total) {
        return TRESTLE_ERR_NOMEM;
    }
    used += trestle_nvram_chrp_partition(storage + used, size - used,
                                         NVRAM_CHRP_SIG_CONFIG, "common", 0,
                                         common_total - sizeof(nvram_chrp_header));
    if (used != size) {
        return TRESTLE_ERR_INVAL;
    }

    return trestle_nvram_parse(nv);
}

// ---------------------------------------------------------------------------
// Device-model entry points.
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
    //     nvram-proxy-data = <nv->image, nv->size>
    //
    // See docs/design.md ("Device tree ownership").
    TRESTLE_UNUSED(node);
    if (nv == 0) {
        return TRESTLE_ERR_INVAL;
    }
    return TRESTLE_ERR_NOTSUP;
}
