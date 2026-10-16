// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/aprr.h - the configuration registers.
//
// Three parts of the same platform service:
//
//   avp-ctrr              Apple's core translation table registers: the region
//                         a guest writes to make ranges of memory (kernel text,
//                         among others) read-only or execute-only.
//                         ml_unsafe_kernel_text_init() reads /chosen
//                         "kernel-ctrr-to-be-enabled" to decide whether to use
//                         it at all.
//   avp-sealed-registers  the write-once configuration registers.
//   chosen/lock-regs      the firmware description of which of them are locked.
//
// Trestle publishes the nodes so the platform services exist, and models the
// windows as a register file that remembers what was written.  The semantics
// beyond that -- which register controls which translation, and how sealing is
// enforced -- are not yet reverse engineered out of the AVP kexts, and the
// model says so rather than pretending.
#ifndef TRESTLE_APRR_H
#define TRESTLE_APRR_H

#include "trestle.h"

#define TRESTLE_APRR_REGS 8

typedef struct {
    trestle_device device;
    const trestle_machine *machine;

    u64 ctrr_offset;
    u64 ctrr_size;
    u64 ctrr_base;
    u64 sealed_offset;
    u64 sealed_size;
    u64 sealed_base;

    u64 ctrr[TRESTLE_APRR_REGS];
    u64 sealed[TRESTLE_APRR_REGS];
} trestle_aprr;

trestle_status trestle_aprr_install(trestle_aprr *aprr);
trestle_status trestle_aprr_start(trestle_device *dev,
                                  const trestle_machine *m);
trestle_status trestle_aprr_contribute(trestle_device *dev, trestle_adt *adt);
trestle_status trestle_aprr_mmio_read(trestle_device *dev, u64 addr,
                                      usize size, u64 *value);
trestle_status trestle_aprr_mmio_write(trestle_device *dev, u64 addr,
                                       usize size, u64 value);

#endif // TRESTLE_APRR_H
