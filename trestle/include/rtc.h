// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/rtc.h - the real-time clock.
//
// Two devices, one model:
//
//   pl031-rtc  a PL031: a 32-bit seconds counter with a match register and a
//              level interrupt.  QEMU's virt machine has a real one, and the
//              AVP has one too (AppleVirtualPlatform registers ApplePL031RTC
//              for it).  Modelled here in full, because a clock that does not
//              advance breaks the kernel's time base and, later, the RTC
//              service userland reads the wall clock from.
//
//   avp-rtc    Apple's paravirtual RTC (AppleVirtualPlatformRTC).  Published
//              when the machine provides its window.  Its register protocol is
//              not yet reverse engineered out of the AVP kexts, so the model
//              accepts accesses and returns zero rather than faulting: the
//              node exists, the driver binds, and the gap is explicit.
#ifndef TRESTLE_RTC_H
#define TRESTLE_RTC_H

#include "trestle.h"

typedef struct {
    trestle_device device;

    // From the machine description.  The offset is relative to the SoC base
    // (what "reg" publishes); the base is absolute (what MMIO arrives at).
    u64 pl031_offset;
    u64 pl031_size;
    u64 pl031_base;
    u32 pl031_irq;
    u64 avp_offset;
    u64 avp_size;
    u64 avp_base;
    u32 avp_irq;

    // Time source: the machine's free-running counter and its frequency.  The
    // PL031 counts seconds, so the model counts them off this; without one the
    // clock holds epoch_base forever.
    u64 (*counter)(void);
    u32  counter_hz;
    u64  epoch_base;      // seconds since 1970 when the register was loaded
    u64  load_counter;    // counter value at that moment

    // PL031 register file.
    u32 lr;
    u32 mr;
    u32 cr;
    u32 imsc;
    u32 ris_acked;
} trestle_rtc;

// Install the model and its time source.  `counter` is the machine's
// free-running counter (CNTVCT_EL0 on aarch64), `hz` its frequency, and
// `epoch` the wall-clock second it should be read as.  Passing counter == NULL
// is allowed: the clock then reports `epoch` and never advances.
trestle_status trestle_rtc_install(trestle_rtc *rtc, u64 (*counter)(void),
                                   u32 hz, u64 epoch);

// Device contract: resolve this machine's windows and publish the nodes.
trestle_status trestle_rtc_start(trestle_device *dev,
                                 const trestle_machine *m);
trestle_status trestle_rtc_contribute(trestle_device *dev, trestle_adt *adt);
trestle_status trestle_rtc_mmio_read(trestle_device *dev, u64 addr, usize size,
                                     u64 *value);
trestle_status trestle_rtc_mmio_write(trestle_device *dev, u64 addr,
                                      usize size, u64 value);

// What the clock reads now, in seconds since 1970.
u32 trestle_rtc_now(const trestle_rtc *rtc);

#endif // TRESTLE_RTC_H
