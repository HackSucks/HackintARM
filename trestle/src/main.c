// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/main.c - Trestle entry point.
//
// Trestle is loaded by Gatehouse before XNU.  It owns the platform: the device
// models that stand in for Apple's AVP hardware and the device tree that
// describes them, both built from a machine description (include/machines.h)
// so that the same Trestle runs on QEMU's virt machine and on real hardware.
//
// The work is in src/boot.c (the platform), src/platform_nodes.c (the platform
// contract's own nodes) and one file per device model.  This file is what a
// boot hands control to: it owns the tree's storage, reads the machine's clock
// and plants the serialised tree where boot_args says it goes.
#include "boot.h"
#include "machines.h"
#include "trestle.h"

#include "adt.h"

// The tree builder's storage.  There is no allocator, so the arena, the node
// table and the property table are sized for the platform's tree plus the
// NVRAM image it carries (8 KiB) and the boot seed (256 bytes).
#define TRESTLE_ADT_DATA_BYTES (128 * 1024)
#define TRESTLE_ADT_NODES      96
#define TRESTLE_ADT_PROPS      1024
#define TRESTLE_ADT_OUT_BYTES  (96 * 1024)

static u8               g_adt_data[TRESTLE_ADT_DATA_BYTES];
static trestle_adt_prop g_adt_props[TRESTLE_ADT_PROPS];
static trestle_adt_node g_adt_nodes[TRESTLE_ADT_NODES];
static trestle_adt      g_adt;
static u8               g_adt_out[TRESTLE_ADT_OUT_BYTES];

// The machine's free-running counter.  On aarch64 that is the virtual counter,
// which is the time base the platform declares; the host build (the model
// tests) has none, and the clock then does not advance.
static u64 trestle_counter(void)
{
#if defined(__aarch64__)
    u64 value;

    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(value));
    return value;
#else
    return 0;
#endif
}

// The counter's frequency.  It is the frequency the tree declares as well --
// XNU's pe_identify_machine() reads that property into its time base -- so
// the clock model and the machine description have to agree.
static u32 trestle_counter_hz(void)
{
#if defined(__aarch64__)
    u64 value;

    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return (u32)value;
#else
    return 0;
#endif
}

trestle_status trestle_main(const trestle_machine *machine)
{
    trestle_boot_clock clock;
    trestle_status     st;
    usize              written = 0;
    usize              i;

    if (machine == 0)
        machine = trestle_machine_qemu_virt();

    st = trestle_adt_init(&g_adt, g_adt_data, sizeof(g_adt_data),
                          g_adt_props, TRESTLE_ARRAY_SIZE(g_adt_props),
                          g_adt_nodes, TRESTLE_ARRAY_SIZE(g_adt_nodes));
    if (st != TRESTLE_OK)
        return st;

    clock.counter = trestle_counter;
    clock.counter_hz = trestle_counter_hz();
    clock.epoch = 0;

    st = trestle_boot_platform(machine, &clock, &g_adt);
    if (st != TRESTLE_OK)
        return st;

    st = trestle_adt_serialize(&g_adt, g_adt_out, sizeof(g_adt_out), &written);
    if (st != TRESTLE_OK)
        return st;

    // Hand the tree to the boot.  Gatehouse seeds boot_args->deviceTreeP with
    // this address; a machine description that leaves dt_base zero has the
    // tree left in place for the caller to take.
    if (machine->dt_base != 0) {
        if (written > machine->dt_capacity)
            return TRESTLE_ERR_NOMEM;
        for (i = 0; i < written; i++)
            ((u8 *)(usize)machine->dt_base)[i] = g_adt_out[i];
    }
    return TRESTLE_OK;
}
