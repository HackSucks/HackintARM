// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/nvram.h - the NVRAM device model.
//
// XNU reaches non-volatile storage through IONVRAMCHRPHandler, which takes the
// store from the device tree: the /chosen property "nvram-proxy-data" is an
// image of 16-byte-aligned CHRP partitions and "nvram-total-size" is its size.
// The layout is defined by Apple's open-source iokit/Kernel/IONVRAM.cpp:
//
//     struct chrp_nvram_header {              // 16 bytes
//         u8  sig;                            // 0x70 system, 0x71 config
//         u8  cksum;                          // header bytes sum to zero
//         u16 len;                            // length in 16-byte blocks
//         char name[12];                      // "system" / "common"
//     };
//
// This device owns that image and answers reads and writes to it.  It is the
// first Trestle device because it is small, self-contained and on the boot
// critical path.
#ifndef TRESTLE_NVRAM_H
#define TRESTLE_NVRAM_H

#include "trestle.h"

#define NVRAM_CHRP_SIG_SYSTEM   0x70
#define NVRAM_CHRP_SIG_CONFIG   0x71
#define NVRAM_CHRP_BLOCK        0x10            // len is in 16-byte blocks
#define NVRAM_CHRP_NAME_LEN     12

#define NVRAM_DEFAULT_SIZE      8192            // what iBoot uses on Apple e
#define NVRAM_MAX_SIZE          (64 * 1024)

typedef struct {
    u8  sig;
    u8  cksum;
    u16 len;                                    // in NVRAM_CHRP_BLOCK units
    char name[NVRAM_CHRP_NAME_LEN];
} __attribute__((packed)) nvram_chrp_header;

typedef struct trestle_nvram {
    trestle_device device;                      // must be first: the vtable

    u8      *image;                             // CHRP image, `size` bytes
    usize    size;
    u64      generation;
    int      dirty;

    u32      system_partition_offset;
    u32      system_partition_size;
    u32      common_partition_offset;
    u32      common_partition_size;
} trestle_nvram;

// Initialise `nv` to back a `size`-byte store held in `storage`.  Builds an
// empty but well-formed image (a "system" and a "common" partition).  Passing
// size == 0 selects NVRAM_DEFAULT_SIZE.
trestle_status trestle_nvram_init(trestle_nvram *nv, u8 *storage, usize size);

// Encode one CHRP partition (header + `data` bytes, zero-padded to a block)
// into `out`, which must hold at least nvram_chrp_partition_size() bytes.
// Returns the number of bytes written, or 0 on error.
usize trestle_nvram_chrp_partition(u8 *out, usize out_size, u8 sig,
                                   const char *name, const void *data,
                                   usize data_size);
usize trestle_nvram_chrp_partition_size(usize data_size);

// Walk the image and record the system/common partition geometry.
trestle_status trestle_nvram_parse(trestle_nvram *nv);

// Device-model entry points (used when it is registered as a trestle_device).
trestle_status trestle_nvram_contribute(trestle_device *dev, void *node);

#endif // TRESTLE_NVRAM_H
