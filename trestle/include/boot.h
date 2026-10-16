// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/boot.h - assembling the platform.
#ifndef TRESTLE_BOOT_H
#define TRESTLE_BOOT_H

#include "trestle.h"

// The boot clock: the free-running counter the machine's time base runs from,
// its frequency, and the wall-clock second that counter reads as.  It is
// separate from the machine description because it is a property of the boot
// (the architected counter is per-cpu state, not a device), and because a host
// build has no counter to read.
typedef struct {
    u64 (*counter)(void);       // NULL: time does not advance
    u32   counter_hz;
    u64   epoch;                // seconds since 1970
} trestle_boot_clock;

// Assemble Trestle's platform for `machine`: install every device model,
// register it, start it (which resolves the machine's windows), and then have
// the platform and the devices publish their nodes into `adt`, which must
// already be initialised.  Returns the first failure.
//
// This is the whole of "which devices Trestle has"; the device tree it lands
// in is the caller's (include/adt.h), because where the tree goes and what it
// is serialised into are boot decisions.
trestle_status trestle_boot_platform(const trestle_machine *machine,
                                     const trestle_boot_clock *clock,
                                     trestle_adt *adt);

#endif // TRESTLE_BOOT_H
