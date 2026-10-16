// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/trestle.h - core types for the Trestle platform.
//
// Trestle is the HackintARM platform layer.  It provides the Apple virtual
// platform ("AVP") semantics that XNU expects on machines that are not Apple
// Silicon: the device tree, the platform devices, and the services the kernel
// looks up by name or by device-tree path.  It is deliberately freestanding
// and machine-portable -- see docs/design.md.
#ifndef TRESTLE_H
#define TRESTLE_H

typedef unsigned char      u8;
typedef signed char        s8;
typedef unsigned short     u16;
typedef signed short       s16;
typedef unsigned int       u32;
typedef signed int         s32;
typedef unsigned long      u64;
typedef signed long        s64;
typedef unsigned long      usize;

#define TRESTLE_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define TRESTLE_UNUSED(x)     ((void)(x))

typedef enum {
    TRESTLE_OK = 0,
    TRESTLE_ERR_INVAL,       // bad argument
    TRESTLE_ERR_NOMEM,       // out of space
    TRESTLE_ERR_NOTFOUND,    // no such device/node
    TRESTLE_ERR_NOTSUP,      // unsupported operation
} trestle_status;

// The platform hands devices a description of the machine it is running on.
// Keeping this separate from the device models is what makes them portable:
// a device never reaches for a fixed physical address itself.
typedef struct {
    u64  ram_base;
    u64  ram_size;
    u64  dt_base;            // physical address of the (native) device tree
    u64  dt_size;
    void *log_write;         // sink for the platform log (may be NULL)
} trestle_machine;

struct trestle_platform;

// A device model.  Every model implements the same contract regardless of the
// machine it runs on; the *transport* (EL2 trap, MMIO window, ...) is supplied
// by the platform, not the device.
typedef struct trestle_device {
    const char             *name;
    trestle_status        (*init)(struct trestle_device *dev,
                                  const trestle_machine *m);
    // Contribute device-tree nodes/properties for this device.  `node` is an
    // opaque handle owned by the device-tree builder.
    trestle_status        (*adt_contribute)(struct trestle_device *dev,
                                            void *node);
    trestle_status        (*mmio_read)(struct trestle_device *dev, u64 addr,
                                       usize size, u64 *value);
    trestle_status        (*mmio_write)(struct trestle_device *dev, u64 addr,
                                        usize size, u64 value);
    void                  (*deinit)(struct trestle_device *dev);
} trestle_device;

// Platform registry.  Platforms are little more than an ordered list of
// devices plus the machine description.
typedef struct trestle_platform {
    const trestle_machine          *machine;
    const trestle_device          **devices;
    usize                           count;
    usize                           capacity;
} trestle_platform;

trestle_status trestle_platform_init(trestle_platform *p,
                                     const trestle_machine *m,
                                     const trestle_device **devices,
                                     usize capacity);
trestle_status trestle_platform_register(trestle_platform *p,
                                         const trestle_device *dev);
trestle_status trestle_platform_start(trestle_platform *p);

// Entry point.  Called once the machine description is known, before XNU runs.
trestle_status trestle_main(const trestle_machine *machine);

#endif // TRESTLE_H
