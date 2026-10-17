// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/include/pcie.h - the PCIe host bridge.
//
// The AVP's PCIe host is what the root disk is behind.  XNU's storage stack is
// AppleVirtIOStorageDevice sitting on AppleVirtIOTransport, and the transport
// that publishes it matches the *generic* virtio PCI ids (AppleVirtIOBlock
// carries IOVirtIOPrimaryMatch = 0x00021af4, i.e. virtio device type 2 vendor
// 0x1af4), so the disk itself is an ordinary virtio-blk.  What has to be right
// is the bridge: AppleVirtualPlatformPCIE matches a /arm-io child whose
// "compatible" is "pcie,vmapple1", maps its "reg" as the ECAM, takes its
// decode windows from "ranges", takes the first INTx GIC id from
// "interrupt-base", and resolves "device-interrupt-parent" to register the
// interrupt.
//
// What this model does *not* do yet is back the device: the ECAM, the config
// space, the BAR decode windows, INTx delivery and the GICv2m-shaped MSI frame
// (the GIC's third "reg" region, selected by "msi-frame-index") are the work
// items for a machine that has to emulate the AVP, and they are why the AVP
// description here publishes nodes for devices this tree cannot yet service.
// For the bring-up machine QEMU supplies the bridge (GPEX) and the model only
// has to describe it, which is what the node below is for -- the two trees
// have to agree (tools/adt_diff.py), and a machine with no "pcie" window
// publishes nothing.
#ifndef TRESTLE_PCIE_H
#define TRESTLE_PCIE_H

#include "trestle.h"

typedef struct {
    trestle_device device;

    // From the machine description.  Offsets are relative to the SoC base
    // (what "reg" and "ranges" publish); the CPU-side base is absolute.
    u64 ecam_offset;
    u64 ecam_size;
    u64 mmio_offset;
    u64 mmio_size;
    u64 mmio_pci_base;      // the CPU/PCI absolute base of that window
    u64 msi_frame_offset;
    u64 msi_frame_size;
    u32 intx_base;          // raw GIC id of INTx pin 0, e.g. 35 or 0x40
} trestle_pcie;

// Install the model.  Nothing to configure: the windows come from the machine.
trestle_status trestle_pcie_install(trestle_pcie *pcie);

// Device contract: resolve this machine's windows and publish the node.
trestle_status trestle_pcie_start(trestle_device *dev,
                                  const trestle_machine *m);
trestle_status trestle_pcie_contribute(trestle_device *dev, trestle_adt *adt);

#endif // TRESTLE_PCIE_H
