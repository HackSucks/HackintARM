// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/aprr.c - the CTRR and sealed-register windows.
#include "aprr.h"

#include "adt.h"
#include "platform_nodes.h"

// The registers are 64-bit and the windows are one page each, so the file is
// indexed by the word offset within the window.
#define APRR_STRIDE 8

static int aprr_index(u64 offset, u64 size, u64 *index)
{
    u64 slot = offset / APRR_STRIDE;

    if (offset + APRR_STRIDE > size || (offset % APRR_STRIDE) != 0)
        return 0;
    *index = slot % TRESTLE_APRR_REGS;
    return 1;
}

trestle_status trestle_aprr_install(trestle_aprr *aprr)
{
    int i;

    if (aprr == 0)
        return TRESTLE_ERR_INVAL;

    aprr->device.name = "aprr";
    aprr->device.init = trestle_aprr_start;
    aprr->device.adt_contribute = trestle_aprr_contribute;
    aprr->device.mmio_read = trestle_aprr_mmio_read;
    aprr->device.mmio_write = trestle_aprr_mmio_write;
    aprr->device.deinit = 0;

    aprr->machine = 0;
    aprr->ctrr_offset = aprr->ctrr_size = aprr->ctrr_base = 0;
    aprr->sealed_offset = aprr->sealed_size = aprr->sealed_base = 0;
    for (i = 0; i < TRESTLE_APRR_REGS; i++) {
        aprr->ctrr[i] = 0;
        aprr->sealed[i] = 0;
    }
    return TRESTLE_OK;
}

trestle_status trestle_aprr_start(trestle_device *dev,
                                  const trestle_machine *m)
{
    trestle_aprr                 *aprr = (trestle_aprr *)dev;
    const trestle_machine_window *w;

    if (aprr == 0 || m == 0)
        return TRESTLE_ERR_INVAL;

    aprr->machine = m;
    w = trestle_machine_find_window(m, "avp-ctrr");
    if (w != 0) {
        aprr->ctrr_offset = w->offset;
        aprr->ctrr_size = w->size;
        aprr->ctrr_base = m->soc_base + w->offset;
    }
    w = trestle_machine_find_window(m, "avp-sealed-registers");
    if (w != 0) {
        aprr->sealed_offset = w->offset;
        aprr->sealed_size = w->size;
        aprr->sealed_base = m->soc_base + w->offset;
    }
    return TRESTLE_OK;
}

trestle_status trestle_aprr_contribute(trestle_device *dev, trestle_adt *adt)
{
    trestle_aprr *aprr = (trestle_aprr *)dev;
    int           arm_io;

    if (aprr == 0 || adt == 0)
        return TRESTLE_ERR_INVAL;
    arm_io = trestle_adt_find(adt, "/arm-io");
    if (arm_io == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOTFOUND;

    if (aprr->ctrr_base != 0) {
        u64 reg[2] = { aprr->ctrr_offset, aprr->ctrr_size };
        int node = trestle_adt_add_node(adt, arm_io, "avp-ctrr");

        if (node == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOMEM;
        trestle_adt_set_string(adt, node, "compatible", "avp,ctrr");
        trestle_adt_set_u32(adt, node, "AAPL,phandle",
                            TRESTLE_PHANDLE_AVP_CTRR);
        trestle_adt_set_u64v(adt, node, "reg", reg, 2);
    }

    if (aprr->sealed_base != 0) {
        u64 reg[2] = { aprr->sealed_offset, aprr->sealed_size };
        int node = trestle_adt_add_node(adt, arm_io, "avp-sealed-registers");

        if (node == TRESTLE_ADT_NO_NODE)
            return TRESTLE_ERR_NOMEM;
        trestle_adt_set_string(adt, node, "compatible",
                               "avp,sealed-registers");
        trestle_adt_set_u32(adt, node, "AAPL,phandle",
                            TRESTLE_PHANDLE_AVP_SEALED_REGISTERS);
        trestle_adt_set_u64v(adt, node, "reg", reg, 2);
    }

    // /chosen/lock-regs is the firmware's own description of the lock
    // registers; iBoot publishes it empty (a phandle and nothing else) and the
    // platform's configuration code fills it in as it seals registers.
    {
        int chosen = trestle_adt_find(adt, "/chosen");

        if (chosen != TRESTLE_ADT_NO_NODE) {
            int node = trestle_adt_add_node(adt, chosen, "lock-regs");

            if (node == TRESTLE_ADT_NO_NODE)
                return TRESTLE_ERR_NOMEM;
            trestle_adt_set_u32(adt, node, "AAPL,phandle",
                                TRESTLE_PHANDLE_LOCK_REGS);
        }
    }
    return TRESTLE_OK;
}

trestle_status trestle_aprr_mmio_read(trestle_device *dev, u64 addr,
                                      usize size, u64 *value)
{
    trestle_aprr *aprr = (trestle_aprr *)dev;
    u64           offset;
    u64           index;

    if (aprr == 0 || value == 0 || size != 8)
        return TRESTLE_ERR_INVAL;

    if (aprr->ctrr_base != 0 && addr >= aprr->ctrr_base &&
        addr < aprr->ctrr_base + aprr->ctrr_size) {
        offset = addr - aprr->ctrr_base;
        if (!aprr_index(offset, aprr->ctrr_size, &index))
            return TRESTLE_ERR_INVAL;
        *value = aprr->ctrr[index];
        return TRESTLE_OK;
    }
    if (aprr->sealed_base != 0 && addr >= aprr->sealed_base &&
        addr < aprr->sealed_base + aprr->sealed_size) {
        offset = addr - aprr->sealed_base;
        if (!aprr_index(offset, aprr->sealed_size, &index))
            return TRESTLE_ERR_INVAL;
        *value = aprr->sealed[index];
        return TRESTLE_OK;
    }
    return TRESTLE_ERR_NOTFOUND;
}

trestle_status trestle_aprr_mmio_write(trestle_device *dev, u64 addr,
                                       usize size, u64 value)
{
    trestle_aprr *aprr = (trestle_aprr *)dev;
    u64           offset;
    u64           index;

    if (aprr == 0 || size != 8)
        return TRESTLE_ERR_INVAL;

    if (aprr->ctrr_base != 0 && addr >= aprr->ctrr_base &&
        addr < aprr->ctrr_base + aprr->ctrr_size) {
        offset = addr - aprr->ctrr_base;
        if (!aprr_index(offset, aprr->ctrr_size, &index))
            return TRESTLE_ERR_INVAL;
        aprr->ctrr[index] = value;
        return TRESTLE_OK;
    }
    if (aprr->sealed_base != 0 && addr >= aprr->sealed_base &&
        addr < aprr->sealed_base + aprr->sealed_size) {
        offset = addr - aprr->sealed_base;
        if (!aprr_index(offset, aprr->sealed_size, &index))
            return TRESTLE_ERR_INVAL;
        aprr->sealed[index] = value;
        return TRESTLE_OK;
    }
    return TRESTLE_ERR_NOTFOUND;
}
