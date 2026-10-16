// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/main.c - Trestle entry point.
//
// Trestle is loaded by Gatehouse before XNU.  It owns the platform: the device
// models that stand in for Apple's AVP hardware, and (eventually) the device
// tree that describes them.  Today it brings up the NVRAM device model; the
// platform, the device tree and the EL2 trap layer grow from here.
#include "nvram.h"
#include "trestle.h"

// Backing store for the NVRAM image.  A static buffer keeps bring-up free of
// an allocator; it will move to a Trestle heap once one exists, and to
// persistent storage once the store outlives a boot.
static u8           g_nvram_image[NVRAM_DEFAULT_SIZE];
static trestle_nvram g_nvram;

static const trestle_device *g_devices[8];

trestle_status trestle_main(const trestle_machine *machine)
{
    trestle_platform platform;
    trestle_status  st;

    st = trestle_nvram_init(&g_nvram, g_nvram_image, sizeof(g_nvram_image));
    if (st != TRESTLE_OK) {
        return st;
    }
    g_nvram.device.name = "nvram";

    st = trestle_platform_init(&platform, machine, g_devices,
                               TRESTLE_ARRAY_SIZE(g_devices));
    if (st != TRESTLE_OK) {
        return st;
    }

    st = trestle_platform_register(&platform, &g_nvram.device);
    if (st != TRESTLE_OK) {
        return st;
    }

    return trestle_platform_start(&platform);
}
