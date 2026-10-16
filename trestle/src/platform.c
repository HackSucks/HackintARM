// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/platform.c - the device registry.
#include "trestle.h"

trestle_status trestle_platform_init(trestle_platform *p,
                                     const trestle_machine *m,
                                     const trestle_device **devices,
                                     usize capacity)
{
    if (p == 0 || m == 0 || devices == 0 || capacity == 0) {
        return TRESTLE_ERR_INVAL;
    }
    p->machine = m;
    p->devices = devices;
    p->count = 0;
    p->capacity = capacity;
    return TRESTLE_OK;
}

trestle_status trestle_platform_register(trestle_platform *p,
                                         const trestle_device *dev)
{
    if (p == 0 || dev == 0) {
        return TRESTLE_ERR_INVAL;
    }
    if (p->count >= p->capacity) {
        return TRESTLE_ERR_NOMEM;
    }
    p->devices[p->count++] = dev;
    return TRESTLE_OK;
}

trestle_status trestle_platform_start(trestle_platform *p)
{
    if (p == 0 || p->machine == 0) {
        return TRESTLE_ERR_INVAL;
    }
    for (usize i = 0; i < p->count; i++) {
        const trestle_device *dev = p->devices[i];
        if (dev->init != 0) {
            trestle_status st = dev->init((trestle_device *)dev, p->machine);
            if (st != TRESTLE_OK) {
                return st;
            }
        }
    }
    return TRESTLE_OK;
}
