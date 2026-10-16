// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/machines.h - the machine descriptions.
#ifndef TRESTLE_MACHINES_H
#define TRESTLE_MACHINES_H

#include "trestle.h"

// A machine description is the whole of "where this machine's hardware is and
// what it calls itself".  The device models, the platform and the tree builder
// are machine-independent: moving Trestle to another machine means writing
// another one of these, not another set of device models.
//
// trestle_machine_qemu_virt()
//     the bring-up target.  QEMU's virt machine under an AAVMF firmware is
//     where the port is developed and tested: it has the platform's *shape*
//     (a PL011 console, a PL031, a GICv3, a PL061) and none of the AVP's
//     paravirtual devices.
//
// trestle_machine_avp()
//     the Apple virtual platform (VMA2MACOSAP): the device windows the
//     reference device tree describes.  The devices behind them are Trestle's
//     to emulate; see docs/design.md.
//
// Both return a pointer to a static description that stays valid for the life
// of the program.  Note which fields a machine can and cannot know: the device
// windows, the SoC and the identity belong to the machine, while where the tree
// is placed, how much RAM the boot provided and where the panic log was
// reserved come from the *boot* (boot_args).  Those the caller -- Gatehouse --
// fills in on the returned description before calling trestle_main(), which is
// why it is writable.
trestle_machine *trestle_machine_qemu_virt(void);
trestle_machine *trestle_machine_avp(void);

#endif // TRESTLE_MACHINES_H
