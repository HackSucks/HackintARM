// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/panic.c - the panic log region and the pvpanic port.
#include "panic.h"

#include "adt.h"
#include "platform_nodes.h"

// QEMU's pvpanic-mmio has a single event register at offset 0.  Reading it
// reports the events the device supports; writing one reports that the guest
// panicked (bit 0) or crashed and reloaded (bit 1).
#define PVPANIC_EVENT          0x00
#define PVPANIC_PANICKED       0x01
#define PVPANIC_CRASH_LOADED   0x02
#define PVPANIC_SUPPORTED      (PVPANIC_PANICKED | PVPANIC_CRASH_LOADED)

trestle_status trestle_panic_install(trestle_panic *panic)
{
    if (panic == 0)
        return TRESTLE_ERR_INVAL;

    panic->device.name = "panic";
    panic->device.init = trestle_panic_start;
    panic->device.adt_contribute = trestle_panic_contribute;
    panic->device.mmio_read = trestle_panic_mmio_read;
    panic->device.mmio_write = trestle_panic_mmio_write;
    panic->device.deinit = 0;

    panic->machine = 0;
    panic->pvpanic_offset = 0;
    panic->pvpanic_size = 0;
    panic->pvpanic_base = 0;
    panic->events = 0;
    panic->panics = 0;
    panic->on_panic = 0;
    return TRESTLE_OK;
}

trestle_status trestle_panic_start(trestle_device *dev,
                                   const trestle_machine *m)
{
    trestle_panic                 *panic = (trestle_panic *)dev;
    const trestle_machine_window  *w;

    if (panic == 0 || m == 0)
        return TRESTLE_ERR_INVAL;

    panic->machine = m;
    w = trestle_machine_find_window(m, "pvpanic");
    if (w != 0) {
        panic->pvpanic_offset = w->offset;
        panic->pvpanic_size = w->size;
        panic->pvpanic_base = m->soc_base + w->offset;
    }
    return TRESTLE_OK;
}

trestle_status trestle_panic_contribute(trestle_device *dev, trestle_adt *adt)
{
    trestle_panic *panic = (trestle_panic *)dev;

    if (panic == 0 || adt == 0)
        return TRESTLE_ERR_INVAL;

    // /pram: what check_for_panic_log() maps.  The size is the platform's
    // reservation, so a machine that reserved nothing publishes no node.
    if (panic->machine != 0 && panic->machine->panic_phys != 0) {
        u64 reg[2];
        int node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "pram");

        if (node == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOMEM;
        trestle_adt_set_string(adt, node, "device_type", "pram");
        trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_PRAM);
        reg[0] = panic->machine->panic_phys;
        reg[1] = panic->machine->panic_size;
        trestle_adt_set_u64v(adt, node, "reg", reg, 2);
    }

    if (panic->machine != 0 && panic->machine->panic_size != 0) {
        int chosen = trestle_adt_find(adt, "/chosen");

        if (chosen != TRESTLE_ADT_NO_NODE) {
            trestle_adt_set_u32(adt, chosen, "embedded-panic-log-size",
                                (u32)panic->machine->panic_size);
        }
    }

    if (panic->pvpanic_base != 0) {
        u64 reg[2] = { panic->pvpanic_offset, panic->pvpanic_size };
        int arm_io = trestle_adt_find(adt, "/arm-io");
        int node;

        if (arm_io == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOTFOUND;
        node = trestle_adt_add_node(adt, arm_io, "pvpanic");
        if (node == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOMEM;
        trestle_adt_set_string(adt, node, "compatible", "qemu,pvpanic-mmio");
        trestle_adt_set_u32(adt, node, "AAPL,phandle",
                            TRESTLE_PHANDLE_PVPANIC);
        trestle_adt_set_u64v(adt, node, "reg", reg, 2);
    }
    return TRESTLE_OK;
}

trestle_status trestle_panic_mmio_read(trestle_device *dev, u64 addr,
                                       usize size, u64 *value)
{
    trestle_panic *panic = (trestle_panic *)dev;
    u64           offset;

    if (panic == 0 || value == 0 || size != 1)
        return TRESTLE_ERR_INVAL;
    if (panic->pvpanic_base == 0 || addr < panic->pvpanic_base ||
        addr >= panic->pvpanic_base + panic->pvpanic_size) {
        return TRESTLE_ERR_NOTFOUND;
    }
    offset = addr - panic->pvpanic_base;

    // The capabilities read: what the host is willing to be told about.
    *value = (offset == PVPANIC_EVENT) ? PVPANIC_SUPPORTED : 0;
    return TRESTLE_OK;
}

trestle_status trestle_panic_mmio_write(trestle_device *dev, u64 addr,
                                        usize size, u64 value)
{
    trestle_panic *panic = (trestle_panic *)dev;
    u64           offset;

    if (panic == 0 || size != 1)
        return TRESTLE_ERR_INVAL;
    if (panic->pvpanic_base == 0 || addr < panic->pvpanic_base ||
        addr >= panic->pvpanic_base + panic->pvpanic_size) {
        return TRESTLE_ERR_NOTFOUND;
    }
    offset = addr - panic->pvpanic_base;
    if (offset != PVPANIC_EVENT)
        return TRESTLE_OK;

    panic->events |= (u32)value;
    if ((value & PVPANIC_PANICKED) != 0) {
        // This is the guest telling the host it died.  Hand it to the
        // platform's sink so the run ends with a report instead of a stall.
        panic->panics++;
        if (panic->on_panic != 0)
            panic->on_panic("guest panic (pvpanic)");
    }
    return TRESTLE_OK;
}
