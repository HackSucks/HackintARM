// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// trestle/src/pcie.c - the PCIe host bridge node.
//
// See include/pcie.h for what the platform expects and what is still missing.
#include "pcie.h"
#include "adt.h"
#include "platform_nodes.h"

trestle_status trestle_pcie_install(trestle_pcie *pcie)
{
    if (pcie == 0)
        return TRESTLE_ERR_INVAL;
    pcie->device.name = "pcie";
    pcie->device.init = trestle_pcie_start;
    pcie->device.adt_contribute = trestle_pcie_contribute;
    // No mmio_read/mmio_write: this model describes the bridge, it does not
    // emulate it.  See the header.
    pcie->device.mmio_read = 0;
    pcie->device.mmio_write = 0;
    pcie->device.deinit = 0;
    pcie->ecam_offset = 0;
    pcie->ecam_size = 0;
    pcie->mmio_offset = 0;
    pcie->mmio_size = 0;
    pcie->mmio_pci_base = 0;
    pcie->msi_frame_offset = 0;
    pcie->msi_frame_size = 0;
    pcie->intx_base = 0;
    return TRESTLE_OK;
}

trestle_status trestle_pcie_start(trestle_device *dev,
                                  const trestle_machine *m)
{
    trestle_pcie                  *pcie = (trestle_pcie *)dev;
    const trestle_machine_window *w;

    if (pcie == 0 || m == 0)
        return TRESTLE_ERR_INVAL;

    w = trestle_machine_find_window(m, "pcie");
    if (w != 0) {
        pcie->ecam_offset = w->offset;
        pcie->ecam_size = w->size;
        pcie->intx_base = w->irq;
    }
    w = trestle_machine_find_window(m, "pcie-mmio");
    if (w != 0) {
        pcie->mmio_offset = w->offset;
        pcie->mmio_size = w->size;
        pcie->mmio_pci_base = m->soc_base + w->offset;
    }
    // The GIC's message-based-interrupt frame, where the machine has one.  Its
    // absence is why this model publishes no "msi-frame-index": a machine with
    // only the ITS (QEMU virt) cannot service the AVP's GICv2m-shaped frames,
    // so the guest has to fall back to INTx.
    w = trestle_machine_find_window(m, "gic-msi-frame");
    if (w != 0) {
        pcie->msi_frame_offset = w->offset;
        pcie->msi_frame_size = w->size;
    }
    return TRESTLE_OK;
}

trestle_status trestle_pcie_contribute(trestle_device *dev, trestle_adt *adt)
{
    const trestle_pcie *pcie = (const trestle_pcie *)dev;
    int                 arm_io;
    int                 n;
    u64                 reg[2];
    u32                 cells[2];

    if (pcie == 0 || adt == 0)
        return TRESTLE_ERR_INVAL;
    if (pcie->ecam_size == 0 || pcie->mmio_size == 0)
        return TRESTLE_OK;              // no bridge on this machine

    arm_io = trestle_adt_find(adt, "/arm-io");
    if (arm_io == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOTFOUND;

    n = trestle_adt_add_node(adt, arm_io, "pcie");
    if (n == TRESTLE_ADT_NO_NODE)
        return TRESTLE_ERR_NOMEM;

    trestle_adt_set_string(adt, n, "compatible", "pcie,vmapple1");
    trestle_adt_set_string(adt, n, "device_type", "pci");
    trestle_adt_set_u32(adt, n, "AAPL,phandle", TRESTLE_PHANDLE_PCIE);
    // A PCI child address is <phys.hi phys.mid phys.lo>, as the reference tree
    // publishes it.
    trestle_adt_set_u32(adt, n, "#address-cells", 3);
    trestle_adt_set_u32(adt, n, "#size-cells", 2);

    // The reference platform has nine root ports, so its bus range is 0..8.
    // A machine whose ECAM is smaller still scans no bus it does not have: a
    // config read for an absent bus returns all ones.
    cells[0] = 0;
    cells[1] = 8;
    trestle_adt_set_u32v(adt, n, "bus-range", cells, 2);
    cells[1] = 0xff;
    trestle_adt_set_u32v(adt, n, "dev-range", cells, 2);

    // reg is the ECAM, an offset from the SoC base like every other device.
    reg[0] = pcie->ecam_offset;
    reg[1] = pcie->ecam_size;
    trestle_adt_set_u64v(adt, n, "reg", reg, 2);

    // ranges is the standard <child address: 3, parent address: 2, size: 2>
    // group.  The CPU-side address is SoC-relative, the same convention "reg"
    // uses -- the reference tree says PCI 0x50000000 -> CPU 0x40000000 with the
    // SoC base at 0x10000000, which is the identity mapping the platform
    // implements -- and the PCI side is that same absolute address, because a
    // machine may decode its bus wherever it likes but here it is identity.
    {
        u32 ranges[7];

        ranges[0] = 0x02000000;                     // 32-bit, non-prefetchable
        ranges[1] = (u32)pcie->mmio_pci_base;
        ranges[2] = (u32)(pcie->mmio_pci_base >> 32);
        ranges[3] = (u32)pcie->mmio_offset;
        ranges[4] = (u32)(pcie->mmio_offset >> 32);
        ranges[5] = (u32)pcie->mmio_size;
        ranges[6] = (u32)(pcie->mmio_size >> 32);
        trestle_adt_set_u32v(adt, n, "ranges", ranges, 7);
    }

    // XNU's interrupt cells are raw GIC ids, so this is one too.
    trestle_adt_set_u32(adt, n, "interrupt-base", pcie->intx_base);
    trestle_adt_set_u32(adt, n, "device-interrupt-parent",
                        TRESTLE_PHANDLE_GIC);

    if (pcie->msi_frame_size != 0) {
        trestle_adt_set_u32(adt, n, "msi-frame-index", 2);
    }
    return TRESTLE_OK;
}
