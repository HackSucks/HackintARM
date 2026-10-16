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

// Have every device publish its nodes.  Devices are independent, so one that
// has nothing to say on this machine is not an error: it simply contributes
// nothing (an absent window is how a device learns it is not present).
trestle_status trestle_platform_contribute(const trestle_platform *p,
                                           trestle_adt *adt)
{
    if (p == 0 || adt == 0) {
        return TRESTLE_ERR_INVAL;
    }
    for (usize i = 0; i < p->count; i++) {
        const trestle_device *dev = p->devices[i];
        if (dev->adt_contribute != 0) {
            trestle_status st = dev->adt_contribute((trestle_device *)dev,
                                                    adt);
            if (st != TRESTLE_OK) {
                return st;
            }
        }
    }
    return TRESTLE_OK;
}

// ---------------------------------------------------------------------------
// The machine description.
// ---------------------------------------------------------------------------
static int machine_name_eq(const char *a, const char *b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

const trestle_machine_window *trestle_machine_find_window(const trestle_machine *m,
                                                     const char *name)
{
    if (m == 0 || name == 0) {
        return 0;
    }
    for (usize i = 0; i < m->window_count; i++) {
        if (machine_name_eq(m->windows[i].name, name)) {
            return &m->windows[i];
        }
    }
    return 0;
}

u64 trestle_machine_window_offset(const trestle_machine *m, const char *name)
{
    const trestle_machine_window *w = trestle_machine_find_window(m, name);

    return w != 0 ? w->offset : 0;
}
