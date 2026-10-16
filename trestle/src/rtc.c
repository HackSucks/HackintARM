// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/rtc.c - the PL031 and the AVP RTC.
#include "rtc.h"

#include "adt.h"
#include "platform_nodes.h"

// PL031 register offsets (ARM DDI 0224).
#define PL031_DR       0x000    // data register: the current time
#define PL031_MR       0x004    // match register
#define PL031_LR       0x008    // load register
#define PL031_CR       0x00c    // control register
#define PL031_IMSC     0x010    // interrupt mask set/clear
#define PL031_RIS      0x014    // raw interrupt status
#define PL031_MIS      0x018    // masked interrupt status
#define PL031_ICR      0x01c    // interrupt clear
#define PL031_PERIPHID 0xfe0    // identification registers
#define PL031_IDREGS   8

// PeriphID0..3 then PCellID0..3: part 0x00141031, designer 0xb105f00d (ARM).
static const u8 pl031_ids[PL031_IDREGS] = {
    0x31, 0x10, 0x14, 0x00,
    0x0d, 0xf0, 0x05, 0xb1,
};

static u64 rtc_elapsed(const trestle_rtc *rtc)
{
    if (rtc->counter == 0 || rtc->counter_hz == 0)
        return 0;
    return (rtc->counter() - rtc->load_counter) / rtc->counter_hz;
}

u32 trestle_rtc_now(const trestle_rtc *rtc)
{
    return (u32)(rtc->lr + rtc_elapsed(rtc));
}

// Which window an access lands in: 0 none, 1 the PL031, 2 the AVP RTC.
static int rtc_in_window(const trestle_rtc *rtc, u64 addr, u64 *offset)
{
    if (rtc->pl031_base != 0 && addr >= rtc->pl031_base &&
        addr < rtc->pl031_base + rtc->pl031_size) {
        *offset = addr - rtc->pl031_base;
        return 1;
    }
    if (rtc->avp_base != 0 && addr >= rtc->avp_base &&
        addr < rtc->avp_base + rtc->avp_size) {
        *offset = addr - rtc->avp_base;
        return 2;
    }
    return 0;
}

// The match register raises the interrupt while the counter is at or past it,
// and ICR acknowledges it -- so the model is an interrupt source, not just a
// constant.
static u32 rtc_ris(const trestle_rtc *rtc)
{
    u32 raw = (rtc->mr != 0 && trestle_rtc_now(rtc) >= rtc->mr) ? 1u : 0u;

    return raw & ~rtc->ris_acked;
}

trestle_status trestle_rtc_install(trestle_rtc *rtc, u64 (*counter)(void),
                                   u32 hz, u64 epoch)
{
    if (rtc == 0)
        return TRESTLE_ERR_INVAL;

    rtc->device.name = "rtc";
    rtc->device.init = trestle_rtc_start;
    rtc->device.adt_contribute = trestle_rtc_contribute;
    rtc->device.mmio_read = trestle_rtc_mmio_read;
    rtc->device.mmio_write = trestle_rtc_mmio_write;
    rtc->device.deinit = 0;

    rtc->pl031_offset = 0;
    rtc->pl031_size = 0;
    rtc->pl031_base = 0;
    rtc->pl031_irq = 0;
    rtc->avp_offset = 0;
    rtc->avp_size = 0;
    rtc->avp_base = 0;
    rtc->avp_irq = 0;

    rtc->counter = counter;
    rtc->counter_hz = hz;
    rtc->epoch_base = epoch;
    rtc->load_counter = counter != 0 ? counter() : 0;

    rtc->lr = (u32)epoch;
    rtc->mr = 0;
    rtc->cr = 1;            // the counter runs
    rtc->imsc = 0;
    rtc->ris_acked = 0;
    return TRESTLE_OK;
}

trestle_status trestle_rtc_start(trestle_device *dev,
                                 const trestle_machine *m)
{
    trestle_rtc                  *rtc = (trestle_rtc *)dev;
    const trestle_machine_window *w;

    if (rtc == 0 || m == 0)
        return TRESTLE_ERR_INVAL;

    w = trestle_machine_find_window(m, "pl031-rtc");
    if (w != 0) {
        rtc->pl031_offset = w->offset;
        rtc->pl031_size = w->size;
        rtc->pl031_base = m->soc_base + w->offset;
        rtc->pl031_irq = w->irq;
    }
    w = trestle_machine_find_window(m, "avp-rtc");
    if (w != 0) {
        rtc->avp_offset = w->offset;
        rtc->avp_size = w->size;
        rtc->avp_base = m->soc_base + w->offset;
        rtc->avp_irq = w->irq;
    }
    return TRESTLE_OK;
}

trestle_status trestle_rtc_contribute(trestle_device *dev, trestle_adt *adt)
{
    trestle_rtc *rtc = (trestle_rtc *)dev;
    int          arm_io;

    if (rtc == 0 || adt == 0)
        return TRESTLE_ERR_INVAL;
    arm_io = trestle_adt_find(adt, "/arm-io");
    if (arm_io == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOTFOUND;

    if (rtc->pl031_base != 0) {
        u64 reg[2] = { rtc->pl031_offset, rtc->pl031_size };
        int n = trestle_adt_add_node(adt, arm_io, "pl031-rtc");

        if (n == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOMEM;
        trestle_adt_set_string(adt, n, "compatible", "ARM,pl031");
        trestle_adt_set_u32(adt, n, "AAPL,phandle", TRESTLE_PHANDLE_PL031_RTC);
        trestle_adt_set_u64v(adt, n, "reg", reg, 2);
        // The AVP's PL031 publishes no interrupt: its driver reads the
        // counter, and the guest never takes an interrupt from it.
    }

    if (rtc->avp_base != 0) {
        u64 reg[2] = { rtc->avp_offset, rtc->avp_size };
        int n = trestle_adt_add_node(adt, arm_io, "avp-rtc");

        if (n == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOMEM;
        trestle_adt_set_string(adt, n, "compatible", "avp,rtc");
        trestle_adt_set_u32(adt, n, "AAPL,phandle",
                            TRESTLE_PHANDLE_AVP_RTC);
        trestle_adt_set_u64v(adt, n, "reg", reg, 2);
        if (rtc->avp_irq != 0) {
            u32 irq[2] = { rtc->avp_irq, 0 };

            trestle_adt_set_u32v(adt, n, "interrupts", irq, 2);
            trestle_adt_set_u32(adt, n, "interrupt-parent",
                                TRESTLE_PHANDLE_GIC);
        }
    }
    return TRESTLE_OK;
}

trestle_status trestle_rtc_mmio_read(trestle_device *dev, u64 addr,
                                     usize size, u64 *value)
{
    trestle_rtc *rtc = (trestle_rtc *)dev;
    u64          offset = 0;

    if (rtc == 0 || value == 0 || size != 4)
        return TRESTLE_ERR_INVAL;

    switch (rtc_in_window(rtc, addr, &offset)) {
    case 1:
        switch (offset) {
        case PL031_DR:
            *value = trestle_rtc_now(rtc);
            return TRESTLE_OK;
        case PL031_MR:
            *value = rtc->mr;
            return TRESTLE_OK;
        case PL031_LR:
            *value = rtc->lr;
            return TRESTLE_OK;
        case PL031_CR:
            *value = rtc->cr;
            return TRESTLE_OK;
        case PL031_IMSC:
            *value = rtc->imsc;
            return TRESTLE_OK;
        case PL031_RIS:
            *value = rtc_ris(rtc);
            return TRESTLE_OK;
        case PL031_MIS:
            *value = rtc->imsc & rtc_ris(rtc);
            return TRESTLE_OK;
        case PL031_ICR:
            *value = 0;             // write-only
            return TRESTLE_OK;
        default:
            // The identification registers are one byte each at a four-byte
            // stride (PeriphID0..3 at 0xfe0..0xfec, PCellID0..3 at
            // 0xff0..0xffc).
            if (offset >= PL031_PERIPHID &&
                offset < PL031_PERIPHID + PL031_IDREGS * 4 &&
                (offset % 4) == 0) {
                *value = pl031_ids[(offset - PL031_PERIPHID) / 4];
            } else {
                *value = 0;
            }
            return TRESTLE_OK;
        }
    case 2:
        // The AVP RTC's protocol is not yet reverse engineered.  The window is
        // accepted and reads as zero so that the driver binds and the gap is
        // visible rather than being a fault.
        *value = 0;
        return TRESTLE_OK;
    default:
        return TRESTLE_ERR_NOTFOUND;
    }
}

trestle_status trestle_rtc_mmio_write(trestle_device *dev, u64 addr,
                                      usize size, u64 value)
{
    trestle_rtc *rtc = (trestle_rtc *)dev;
    u64          offset = 0;

    if (rtc == 0 || size != 4 || value > 0xffffffffu)
        return TRESTLE_ERR_INVAL;

    switch (rtc_in_window(rtc, addr, &offset)) {
    case 1:
        switch (offset) {
        case PL031_MR:
            rtc->mr = (u32)value;
            return TRESTLE_OK;
        case PL031_LR:
            // Loading the register restarts the second counter from here.
            rtc->lr = (u32)value;
            rtc->load_counter = rtc->counter != 0 ? rtc->counter() : 0;
            rtc->ris_acked = 0;
            return TRESTLE_OK;
        case PL031_CR:
            rtc->cr = (u32)value;
            return TRESTLE_OK;
        case PL031_IMSC:
            rtc->imsc = (u32)value;
            return TRESTLE_OK;
        case PL031_ICR:
            rtc->ris_acked |= (u32)value;
            return TRESTLE_OK;
        default:
            // DR is read-only; the identification registers ignore writes.
            return TRESTLE_OK;
        }
    case 2:
        return TRESTLE_OK;
    default:
        return TRESTLE_ERR_NOTFOUND;
    }
}
