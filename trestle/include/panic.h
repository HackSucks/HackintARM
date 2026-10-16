// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/panic.h - the panic device.
//
// Two pieces of the same platform contract:
//
//   pram     the parameter RAM region the platform reserves for the panic log.
//            check_for_panic_log() (pexpert/arm/pe_init.c) takes the address
//            from /pram's "reg" and the size from /chosen
//            "embedded-panic-log-size", maps it and writes the panic text
//            there.  Without the node the kernel trips
//
//                pe_init.c: Assertion failed: panic_info
//
//            and *no* panic can be reported at all -- which is how a panic
//            turns into a silent hang.
//
//   pvpanic  QEMU's paravirtual panic port (compatible "qemu,pvpanic-mmio").
//            Writing bit 0 of its event register tells the host that the guest
//            panicked, which is what turns a QEMU run into a panic report
//            instead of a silent stall.
#ifndef TRESTLE_PANIC_H
#define TRESTLE_PANIC_H

#include "trestle.h"

typedef struct {
    trestle_device device;
    const trestle_machine *machine;

    u64 pvpanic_offset;
    u64 pvpanic_size;
    u64 pvpanic_base;

    // The last event the guest reported, and how many times.
    u32 events;
    u32 panics;

    // Optional sink for the panic reason; the platform supplies whatever it
    // has (a serial write, a log buffer, ...).
    void (*on_panic)(const char *reason);
} trestle_panic;

trestle_status trestle_panic_install(trestle_panic *panic);
trestle_status trestle_panic_start(trestle_device *dev,
                                   const trestle_machine *m);
trestle_status trestle_panic_contribute(trestle_device *dev,
                                        trestle_adt *adt);
trestle_status trestle_panic_mmio_read(trestle_device *dev, u64 addr,
                                       usize size, u64 *value);
trestle_status trestle_panic_mmio_write(trestle_device *dev, u64 addr,
                                        usize size, u64 value);

#endif // TRESTLE_PANIC_H
