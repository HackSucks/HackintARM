// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/boot.c - the platform Trestle brings up.
//
// The device models are listed once, here, and are started against whatever
// machine description the caller supplies.  A model whose hardware this machine
// does not have simply contributes no nodes: that is how the same Trestle runs
// on QEMU's virt machine today and on the Apple virtual platform next.
#include "boot.h"

#include "adt.h"
#include "aprr.h"
#include "nvram.h"
#include "panic.h"
#include "pcie.h"
#include "platform_nodes.h"
#include "pmgr.h"
#include "rtc.h"

// The NVRAM store's backing buffer.  A static keeps bring-up free of an
// allocator; it moves to a Trestle heap once one exists, and to persistent
// storage once the store outlives a boot.
static u8           g_nvram_image[NVRAM_DEFAULT_SIZE];

static trestle_nvram g_nvram;
static trestle_rtc   g_rtc;
static trestle_pmgr  g_pmgr;
static trestle_panic g_panic;
static trestle_aprr  g_aprr;
static trestle_pcie  g_pcie;

static const trestle_device *g_devices[8];

static trestle_status register_device(trestle_platform *platform,
                                      const trestle_device *dev)
{
    return trestle_platform_register(platform, dev);
}

trestle_status trestle_boot_platform(const trestle_machine *machine,
                                     const trestle_boot_clock *clock,
                                     trestle_adt *adt)
{
    trestle_platform platform;
    trestle_status   st;
    u64            (*counter)(void) = 0;
    u32              counter_hz = 0;
    u64              epoch = 0;

    if (machine == 0 || adt == 0)
        return TRESTLE_ERR_INVAL;
    if (clock != 0) {
        counter = clock->counter;
        counter_hz = clock->counter_hz;
        epoch = clock->epoch;
    }

    st = trestle_nvram_init(&g_nvram, g_nvram_image, sizeof(g_nvram_image));
    if (st != TRESTLE_OK)
        return st;

    // The PL031 counts seconds, and the epoch it starts from is the platform's
    // own (the reference machine has no battery-backed clock either).
    st = trestle_rtc_install(&g_rtc, counter, counter_hz, epoch);
    if (st != TRESTLE_OK)
        return st;

    st = trestle_pmgr_install(&g_pmgr);
    if (st != TRESTLE_OK)
        return st;
    st = trestle_panic_install(&g_panic);
    if (st != TRESTLE_OK)
        return st;
    st = trestle_aprr_install(&g_aprr);
    if (st != TRESTLE_OK)
        return st;
    st = trestle_pcie_install(&g_pcie);
    if (st != TRESTLE_OK)
        return st;

    st = trestle_platform_init(&platform, machine, g_devices,
                               TRESTLE_ARRAY_SIZE(g_devices));
    if (st != TRESTLE_OK)
        return st;

    if ((st = register_device(&platform, &g_nvram.device)) != TRESTLE_OK ||
        (st = register_device(&platform, &g_rtc.device)) != TRESTLE_OK ||
        (st = register_device(&platform, &g_pmgr.device)) != TRESTLE_OK ||
        (st = register_device(&platform, &g_panic.device)) != TRESTLE_OK ||
        (st = register_device(&platform, &g_aprr.device)) != TRESTLE_OK ||
        (st = register_device(&platform, &g_pcie.device)) != TRESTLE_OK) {
        return st;
    }

    // Starting resolves each device's windows from the machine description;
    // a device whose hardware is absent ends up with no windows and publishes
    // nothing.
    st = trestle_platform_start(&platform);
    if (st != TRESTLE_OK)
        return st;

    // The platform's own nodes go first: the device nodes hang off nodes the
    // platform creates (/arm-io, /chosen, /product).
    st = trestle_platform_nodes_build(adt, machine);
    if (st != TRESTLE_OK)
        return st;
    return trestle_platform_contribute(&platform, adt);
}
