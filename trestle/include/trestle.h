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
//
// The split is the point of the design:
//
//   * a *device model* implements one piece of the platform (a real PL031, a
//     power manager, a panic device) and knows nothing about where it lives;
//   * the *machine description* says where each device's registers are, how
//     much RAM the machine has, where the SoC window starts, and what the
//     machine calls itself;
//   * the *platform* owns the registry and the device tree, and is the only
//     thing that knows both halves.
//
// Moving Trestle to another machine is therefore a new machine description,
// not a new set of device models.
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

// The device tree builder (include/adt.h).  Devices publish their nodes into
// it; the platform owns it.
struct trestle_adt;
typedef struct trestle_adt trestle_adt;

// A window of MMIO the machine provides for a named device.  `offset` is
// relative to the SoC base -- that is the form /arm-io "ranges" publishes and
// the form every device-tree "reg" in Apple's trees uses -- and `irq` is the
// GIC interrupt id (0 when the device publishes none).
typedef struct {
    const char *name;        // the device-tree node name, e.g. "pl031-rtc"
    u64         offset;      // from soc_base
    u64         size;
    u32         irq;
} trestle_machine_window;

// The machine's identity, as the platform expert publishes it
// (IOPlatformSerialNumber, hw.model, ...).  iBoot fills these in from the
// syscfg region on a real Apple machine; a machine port supplies its own.
typedef struct {
    const char *model;
    const char *target_type;
    const char *target_sub_type;
    const char *manufacturer;
    const char *device_tree_tag;
    const char *serial_number;
    const char *mlb_serial_number;
    const char *region_info;
    const char *model_number;
    const char *config_number;
    const char *regulatory_model_number;
    const char *country_of_origin;
    const char *model_config;
    const char *secure_root_prefix;
    const char *time_stamp;
    // The kernel command line, published on /chosen.
    const char *boot_args;
    // The UUID of the volume the machine boots from, published on /chosen as
    // "boot-uuid".  This is a boot policy value rather than a property of the
    // silicon: iBoot selects the boot volume and hands its UUID to the kernel,
    // which is how IOKitBSDInit (IOKit/IOKitBSDInit.cpp) locates the root media
    // -- it waits for an IOMedia whose UUID matches, and when none ever does it
    // writes "boot-picker-bringup-reason" to NVRAM and parks in the boot
    // picker.  A port supplies the UUID of whatever it boots from; a 36
    // character string (the kernel truncates the value at 37 bytes).
    const char *boot_uuid;
    // /product's identity; see the platform nodes.
    const char *product_name;
    const char *unique_model;
    const char *fdr_product_type;
} trestle_machine_identity;

// The machine Trestle is running on.  Everything a device model needs to know
// about the machine arrives through here; a device never reaches for a fixed
// physical address itself.
typedef struct {
    u64  ram_base;
    u64  ram_size;

    // Where the platform hands XNU its device tree, and how big it is.
    u64  dt_base;
    u64  dt_size;
    u64  dt_capacity;

    // gPESoCBasePhys: the base of the SoC's device window.  Every device's
    // "reg" offset is relative to this, and pe_identify_machine() reads it out
    // of /arm-io "ranges".
    u64  soc_base;
    u64  soc_size;

    // The interrupt controller's two regions, as offsets from soc_base:
    // pe_init_fiq() maps exactly these two out of /arm-io/gic's "reg".
    u64  gic_dist_offset;
    u64  gic_dist_size;
    u64  gic_redist_offset;
    u64  gic_redist_size;

    const trestle_machine_window *windows;
    usize                         window_count;

    // The architected-timer frequency the CPU nodes declare.
    u32  timebase_hz;

    // The panic log the platform reserved: published as /pram's "reg" and as
    // /chosen "embedded-panic-log-size".
    u64  panic_phys;
    u64  panic_size;

    // Boot entropy.  PE_get_random_seed() panics when this is absent, empty or
    // all zero, and its consumer wants the full 256 bytes.
    const u8 *random_seed;
    usize     random_seed_size;

    const trestle_machine_identity *identity;

    // Platform log sink (may be NULL).
    void (*log_write)(const char *message);
} trestle_machine;

// Find a device's MMIO window in the machine description, or NULL.
const trestle_machine_window *trestle_machine_find_window(const trestle_machine *m,
                                                     const char *name);

// The offset of a window from the SoC base, or 0 when the machine has no such
// window.
u64 trestle_machine_window_offset(const trestle_machine *m, const char *name);

struct trestle_platform;

// A device model.  Every model implements the same contract regardless of the
// machine it runs on; the *transport* (EL2 trap, MMIO window, ...) is supplied
// by the platform, not the device.
typedef struct trestle_device {
    const char             *name;
    trestle_status        (*init)(struct trestle_device *dev,
                                  const trestle_machine *m);
    // Publish this device's device-tree nodes and properties.  The device adds
    // nodes wherever they belong (usually under /arm-io, /chosen or /product),
    // using the builder's path lookups; it must tolerate the machine not
    // having the hardware it models.
    trestle_status        (*adt_contribute)(struct trestle_device *dev,
                                            trestle_adt *adt);
    // MMIO access, `addr` being the physical address of the access.  Devices
    // that are not memory mapped leave these NULL.
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

// Have every registered device publish its nodes into `adt`.
trestle_status trestle_platform_contribute(const trestle_platform *p,
                                           trestle_adt *adt);

// Entry point.  Called once the machine description is known, before XNU runs.
trestle_status trestle_main(const trestle_machine *machine);

#endif // TRESTLE_H
