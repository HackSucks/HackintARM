// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/nvram.h - the NVRAM device model.
//
// XNU 27 reaches non-volatile storage through IONVRAM.  Its factory
// (iokit/Kernel/IONVRAM.cpp) looks the store up in the device tree and picks a
// handler from the first bytes of the image store:
//
//     entry = IORegistryEntry::fromPath("/chosen")
//     bank  = entry->getProperty("nvram-bank-size")     // also a size
//     image = entry->getProperty("nvram-proxy-data")
//
//     if (image[0..3] == 0x4e565633 && image[0xe] == 1 && bank >= 0x18)
//         IONVRAMV3Handler::create(this, image, bank)   // with the image
//     else
//         IONVRAMCHRPHandler::create(this, NULL, bank)  // with *no* image
//
// The CHRP branch builds an uninitialised handler that faults on first use, so
// the store must be a V3 image.  That format is a 0x18-byte header followed by
// the variable data:
//
//     struct nvram_v3_header {                // 0x18 bytes
//         uint32_t magic;                     // 0x4e565633
//         uint32_t size;                      // total image size
//         uint32_t region_offset;             // -> handler field 0x30
//         uint8_t  reserved[2];               // 0x0c, 0x0d
//         uint8_t  version;                   // 0x0e == 1
//         uint8_t  reserved2;
//         uint32_t field_10;                  // -> handler field 0x4c
//         uint32_t data_end;                  // -> handler field 0x48 (minus 0x18)
//     };
//
// This device owns that image.  It is the first Trestle device because it is
// small, self-contained and on the boot critical path.
//
// The factory and the handler's init() read these /chosen properties:
//
//     nvram-bank-size     u32   bank size in bytes; also the image size that
//                               IONVRAMV3Handler::create() is called with
//     nvram-bank-count    u32   number of banks
//     nvram-current-bank  u32   active bank
//     nvram-raw           u32   non-zero selects raw interpretation of the
//                               store; must be present or init() fails
//     nvram-proxy-data    data  the V3 image itself
//     nvram-total-size    u32   total store size (bank-size * bank-count)
#ifndef TRESTLE_NVRAM_H
#define TRESTLE_NVRAM_H

#include "trestle.h"

#define NVRAM_V3_MAGIC         0x4E565633u
#define NVRAM_V3_VERSION       1u
#define NVRAM_V3_HEADER_SIZE   0x18

#define NVRAM_DEFAULT_SIZE     8192            // what iBoot uses on Apple Silicon
#define NVRAM_MAX_SIZE         (64 * 1024)

typedef struct {
    u32 magic;
    u32 size;
    u32 region_offset;
    u8  reserved_c;
    u8  reserved_d;
    u8  version;
    u8  reserved_f;
    u32 field_10;
    u32 data_end;
} __attribute__((packed)) nvram_v3_header;

typedef struct trestle_nvram {
    trestle_device   device;                    // must be first: the vtable

    u8              *image;                     // V3 image, `size` bytes
    usize            size;
    nvram_v3_header *header;

    u64              generation;
    int              dirty;
    int              raw;                       // /chosen "nvram-raw"
} trestle_nvram;

// Format `storage` (a `size`-byte buffer) as an empty but well-formed V3
// image.  size == 0 selects NVRAM_DEFAULT_SIZE.  Returns the header written.
nvram_v3_header *trestle_nvram_format(u8 *storage, usize size);

// Initialise `nv` to back the `size`-byte store in `storage`, formatting it if
// it does not already hold a valid V3 image.  size == 0 selects the default.
trestle_status trestle_nvram_init(trestle_nvram *nv, u8 *storage, usize size);

// True when `image` starts with a valid V3 header for `size` bytes.
int trestle_nvram_is_valid(const u8 *image, usize size);

// Device-model entry point: publish the store on /chosen as
// "nvram-total-size"/"nvram-bank-size"/"nvram-proxy-data".  The image is the
// V3 one the factory needs (see the header comment); the tree this lands in is
// Trestle's (include/adt.h), and gatehouse/dt/build_adt.py mirrors the same
// properties for the bring-up tree.
trestle_status trestle_nvram_contribute(trestle_device *dev, trestle_adt *adt);

#endif // TRESTLE_NVRAM_H
