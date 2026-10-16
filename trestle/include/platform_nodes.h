// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/platform_nodes.h - the platform's own device-tree nodes.
//
// Devices publish their own nodes (see trestle_device.adt_contribute).  What is
// left is the platform's: the machine's identity, the interrupt controller, the
// CPUs, /chosen and the firmware policy tables.  Those are not a device model
// because nothing emulates them -- they are the contract XNU boots against.
//
// The phandles are iBoot's own numbering, kept identical to
// gatehouse/dt/build_adt.py so that the bring-up tree and Trestle's tree line
// up node for node (tools/adt_diff.py checks that they do).
#ifndef TRESTLE_PLATFORM_NODES_H
#define TRESTLE_PLATFORM_NODES_H

#include "trestle.h"

#define TRESTLE_PHANDLE_ROOT                  0x01
#define TRESTLE_PHANDLE_BUTTONS               0x02
#define TRESTLE_PHANDLE_MACHINE_TIMEOUTS      0x03
#define TRESTLE_PHANDLE_CHOSEN                0x04
#define TRESTLE_PHANDLE_MANIFEST_PROPS        0x05
#define TRESTLE_PHANDLE_MANIFEST_OBJECT_PROPS 0x06
#define TRESTLE_PHANDLE_BOOT_OBJECT_MANIFESTS 0x07
#define TRESTLE_PHANDLE_SECURE_BOOT_HASHES    0x08
#define TRESTLE_PHANDLE_DYNAMIC_OBJECT_MAP    0x09
#define TRESTLE_PHANDLE_MEMORY_MAP            0x0a
#define TRESTLE_PHANDLE_CARVEOUT_MEMORY_MAP   0x0b
#define TRESTLE_PHANDLE_LOCK_REGS             0x0c
#define TRESTLE_PHANDLE_IBOOT                 0x0d
#define TRESTLE_PHANDLE_MEMORY_REPORT         0x0e
#define TRESTLE_PHANDLE_ZEROIZATION_REPORT    0x0f
#define TRESTLE_PHANDLE_ASMB                  0x10
#define TRESTLE_PHANDLE_OPTIONS               0x11
#define TRESTLE_PHANDLE_CPUS                  0x12
#define TRESTLE_PHANDLE_CPU0                  0x13
#define TRESTLE_PHANDLE_ALIASES               0x33
#define TRESTLE_PHANDLE_MEMORY                0x34
#define TRESTLE_PHANDLE_PMGR                  0x35
#define TRESTLE_PHANDLE_ARM_IO                0x36
#define TRESTLE_PHANDLE_AES                   0x37
#define TRESTLE_PHANDLE_UART0                 0x38
#define TRESTLE_PHANDLE_GIC                   0x39
#define TRESTLE_PHANDLE_AVP_CTRR              0x3a
#define TRESTLE_PHANDLE_AVP_SEALED_REGISTERS  0x3b
#define TRESTLE_PHANDLE_AVP_RTC               0x3c
#define TRESTLE_PHANDLE_PL031_RTC             0x3d
#define TRESTLE_PHANDLE_PVPANIC               0x3e
#define TRESTLE_PHANDLE_PCIE                  0x3f
#define TRESTLE_PHANDLE_PL061_BUTTONS         0x40
#define TRESTLE_PHANDLE_IOSURFACE_MAPPER      0x41
#define TRESTLE_PHANDLE_GFX                   0x42
#define TRESTLE_PHANDLE_CPU_DEBUG_INTERFACE   0x43
#define TRESTLE_PHANDLE_PRAM                  0x44
#define TRESTLE_PHANDLE_VRAM                  0x45
#define TRESTLE_PHANDLE_DEFAULTS              0x46
#define TRESTLE_PHANDLE_PRODUCT               0x47
#define TRESTLE_PHANDLE_PRODUCT_USB           0x48
#define TRESTLE_PHANDLE_PRODUCT_UTIL          0x49
#define TRESTLE_PHANDLE_FILESYSTEMS_PROPS     0x4a
#define TRESTLE_PHANDLE_PORT_VIRTUAL_1        0x4b
#define TRESTLE_PHANDLE_OSENVIRONMENTS        0x4c

// The boot-arg set Gatehouse boots XNU with.  The kernel command line lives in
// boot_args (Gatehouse's main.c), and /chosen "boot-args" is what the platform
// code and userland read back.
#define TRESTLE_BOOT_ARGS \
    "debug=0x14e -v -noprogress serial=1 cpus=1 kextlog=0xfff keepsyms=1 " \
    "exe_boothash_salt=0"

// Build the platform's nodes into `adt`, which must already have its root
// ("device-tree") node.  Devices add theirs independently, so the two may run
// in either order.
trestle_status trestle_platform_nodes_build(trestle_adt *adt,
                                            const trestle_machine *m);

#endif // TRESTLE_PLATFORM_NODES_H
