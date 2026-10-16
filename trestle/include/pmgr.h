// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/pmgr.h - the power manager.
//
// AppleImage4 reads the *root power domain* before it will evaluate the boot
// manifest.  When the power manager never appears it reports
//
//     AppleImage4: root power domain not yet available: 19
//
// and waits, which is one of the ways a boot parks silently.  On the AVP the
// manager is a "/pmgr" node with compatible "ARM,psci" and ApplePSCI drives
// the machine's power domains through the PSCI conduit.
//
// There is no hardware to model and no MMIO window: Trestle *is* the
// hypervisor, so the calls land in trestle_pmgr_psci() and are answered here.
// The node and the domain's availability are what the boot needs.
#ifndef TRESTLE_PMGR_H
#define TRESTLE_PMGR_H

#include "trestle.h"

// PSCI function ids, in their 64-bit-calling-convention form.  SMCCC encodes
// the calling convention in bit 30, so requests are recognised after masking
// that bit rather than by comparing the ids whole.
#define TRESTLE_PSCI_VERSION       0x84000000u
#define TRESTLE_PSCI_CPU_SUSPEND   0xc4000001u
#define TRESTLE_PSCI_CPU_OFF       0x84000002u
#define TRESTLE_PSCI_CPU_ON        0xc4000003u
#define TRESTLE_PSCI_AFFINITY_INFO 0xc4000004u
#define TRESTLE_PSCI_MIGRATE       0xc4000005u
#define TRESTLE_PSCI_SYSTEM_OFF    0x84000008u
#define TRESTLE_PSCI_SYSTEM_RESET  0x84000009u
#define TRESTLE_PSCI_FEATURES      0x8400000au

// The SMCCC calling-convention bit, plus the mask that leaves the function
// number and owning entity alone.
#define TRESTLE_PSCI_CONDUIT_64    0x40000000u
#define TRESTLE_PSCI_ID_MASK       0xbfffffffu

// Return values (PSCI returns a signed value; the negative ones are errors).
#define TRESTLE_PSCI_SUCCESS            0
#define TRESTLE_PSCI_NOT_SUPPORTED     (-1)
#define TRESTLE_PSCI_INVALID_PARAMS    (-2)
#define TRESTLE_PSCI_DENIED            (-3)
#define TRESTLE_PSCI_ALREADY_ON        (-4)

// AFFINITY_INFO answers.
#define TRESTLE_PSCI_AFFINITY_ON       0
#define TRESTLE_PSCI_AFFINITY_OFF      1

typedef struct {
    trestle_device device;
    const trestle_machine *machine;

    u16 version_major;
    u16 version_minor;

    u32 root_domain;            // the AVP's root power domain
    int root_domain_available;
    int started;
} trestle_pmgr;

trestle_status trestle_pmgr_install(trestle_pmgr *pmgr);
trestle_status trestle_pmgr_start(trestle_device *dev,
                                  const trestle_machine *m);
trestle_status trestle_pmgr_contribute(trestle_device *dev, trestle_adt *adt);

// Answer one PSCI call.  The platform's trap layer hands HVC/SMC here.
s64 trestle_pmgr_psci(trestle_pmgr *pmgr, u32 function, u64 arg0, u64 arg1,
                      u64 arg2);

#endif // TRESTLE_PMGR_H
