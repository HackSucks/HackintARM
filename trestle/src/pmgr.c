// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/pmgr.c - the power manager and the PSCI conduit.
#include "pmgr.h"

#include "adt.h"
#include "platform_nodes.h"

trestle_status trestle_pmgr_install(trestle_pmgr *pmgr)
{
    if (pmgr == 0)
        return TRESTLE_ERR_INVAL;

    pmgr->device.name = "pmgr";
    pmgr->device.init = trestle_pmgr_start;
    pmgr->device.adt_contribute = trestle_pmgr_contribute;
    pmgr->device.mmio_read = 0;
    pmgr->device.mmio_write = 0;
    pmgr->device.deinit = 0;

    pmgr->machine = 0;
    // PSCI 1.1 is what the machine answers as; the version is declared here so
    // that a client that asks gets a coherent answer.
    pmgr->version_major = 1;
    pmgr->version_minor = 1;
    pmgr->root_domain = 0;
    pmgr->root_domain_available = 0;
    pmgr->started = 0;
    return TRESTLE_OK;
}

trestle_status trestle_pmgr_start(trestle_device *dev,
                                  const trestle_machine *m)
{
    trestle_pmgr *pmgr = (trestle_pmgr *)dev;

    if (pmgr == 0 || m == 0)
        return TRESTLE_ERR_INVAL;

    pmgr->machine = m;
    pmgr->started = 1;
    // Bringing the manager up *is* making the root domain available: the model
    // has no power rails to sequence, so the domain is on from the moment the
    // platform starts.
    pmgr->root_domain_available = 1;
    return TRESTLE_OK;
}

trestle_status trestle_pmgr_contribute(trestle_device *dev, trestle_adt *adt)
{
    trestle_pmgr *pmgr = (trestle_pmgr *)dev;
    int           node;

    if (pmgr == 0 || adt == 0)
        return TRESTLE_ERR_INVAL;

    // iBoot publishes nothing but the compatible and a phandle here: the
    // domains are the PSCI conduit's business, not the tree's.
    node = trestle_adt_add_node(adt, TRESTLE_ADT_NO_NODE, "pmgr");
    if (node == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;
    trestle_adt_set_string(adt, node, "compatible", "ARM,psci");
    trestle_adt_set_u32(adt, node, "AAPL,phandle", TRESTLE_PHANDLE_PMGR);
    return TRESTLE_OK;
}

// The owning entity is the low 24 bits; the platform owns one of them.
static u32 psci_function(u32 function)
{
    return function & TRESTLE_PSCI_ID_MASK;
}

// A case label has to be a constant expression, so the ids are normalised the
// same way requests are: an SMCCC caller may use either calling convention and
// both land on the same label.
#define PSCI_FN(id) ((id) & TRESTLE_PSCI_ID_MASK)

s64 trestle_pmgr_psci(trestle_pmgr *pmgr, u32 function, u64 arg0, u64 arg1,
                      u64 arg2)
{
    u32 fn;

    TRESTLE_UNUSED(arg1);
    TRESTLE_UNUSED(arg2);

    if (pmgr == 0)
        return TRESTLE_PSCI_NOT_SUPPORTED;
    fn = psci_function(function);

    switch (fn) {
    case PSCI_FN(TRESTLE_PSCI_VERSION):
        return ((s64)pmgr->version_major << 16) | (s64)pmgr->version_minor;

    case PSCI_FN(TRESTLE_PSCI_FEATURES):
        switch (psci_function((u32)arg0)) {
        case PSCI_FN(TRESTLE_PSCI_VERSION):
        case PSCI_FN(TRESTLE_PSCI_FEATURES):
        case PSCI_FN(TRESTLE_PSCI_AFFINITY_INFO):
        case PSCI_FN(TRESTLE_PSCI_CPU_SUSPEND):
        case PSCI_FN(TRESTLE_PSCI_CPU_OFF):
        case PSCI_FN(TRESTLE_PSCI_CPU_ON):
        case PSCI_FN(TRESTLE_PSCI_SYSTEM_OFF):
        case PSCI_FN(TRESTLE_PSCI_SYSTEM_RESET):
            return TRESTLE_PSCI_SUCCESS;
        default:
            return TRESTLE_PSCI_NOT_SUPPORTED;
        }

    case PSCI_FN(TRESTLE_PSCI_AFFINITY_INFO):
        // One CPU, and it is running.
        return arg0 == 0 ? TRESTLE_PSCI_AFFINITY_ON
                         : TRESTLE_PSCI_INVALID_PARAMS;

    case PSCI_FN(TRESTLE_PSCI_CPU_ON):
        // A single-CPU platform: cpu 0 is already on and there is nothing to
        // bring up.
        return arg0 == 0 ? TRESTLE_PSCI_ALREADY_ON
                         : TRESTLE_PSCI_INVALID_PARAMS;

    case PSCI_FN(TRESTLE_PSCI_CPU_OFF):
    case PSCI_FN(TRESTLE_PSCI_CPU_SUSPEND):
    case PSCI_FN(TRESTLE_PSCI_SYSTEM_OFF):
    case PSCI_FN(TRESTLE_PSCI_SYSTEM_RESET):
    case PSCI_FN(TRESTLE_PSCI_MIGRATE):
        return TRESTLE_PSCI_SUCCESS;

    default:
        return TRESTLE_PSCI_NOT_SUPPORTED;
    }
}
