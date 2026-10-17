#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
gatehouse/dt/build_adt.py - build the device tree Gatehouse hands to XNU.

XNU does not read a standard flattened device tree.  boot_args->deviceTreeP must
point at Apple's own encoding -- the one iBoot builds on an Apple SoC, which
m1n1 calls the "ADT" -- and pexpert/gen/device_tree.c parses exactly that.  A
.dtb is the wrong format: its magic (0xd00dfeed) is not in the kernel, and XNU
interprets the first node header as { nProperties, nChildren }, walks off the end
of the blob and panics with

    Device tree pointer outside of device tree region: pointer ..., DTEnd ...

Layout (pexpert/pexpert/device_tree.h, m1n1 proxyclient/m1n1/adt.py):

    DeviceTreeNode         { u32 nProperties; u32 nChildren; }
    DeviceTreeNodeProperty { char name[32]; u32 length; u8 value[length]; }

    node := nProperties, nChildren, nProperties * property, nChildren * node

Property values are opaque bytes; strings carry their NUL (XNU's
SecureDTFindNodeWithStringProperty expects length == strlen + 1), each value is
padded to 4 bytes, and integer properties are stored *little-endian* -- this is a
native structure built by firmware, unlike a .dtb which is big-endian by spec.
iBoot also sets bit 31 of `length` on string values; XNU never tests it, and
this builder does not set it (matching the trees that have booted).

What XNU's arm64 platform code looks for (pexpert/arm/), and therefore what
this tree has to contain:

  * root, name = "device-tree"      -> model, target-type        (pe_init.c)
  * a node named "arm-io"           -> ranges, whose second u64 is
                                       gPESoCBasePhys; 0 means "no SoC" and
                                       disables the serial console entirely
                                       (pe_identify_machine.c)
  * /cpus                           -> children with state = "running" and the
                                       *-frequency properties
                                       (pe_identify_machine.c,
                                        ml_parse_cpu_topology)
  * a node named "defaults"         -> serial-device = <phandle>
                                       (pe_serial.c; missing -> panic)
  * the serial node                 -> AAPL,phandle, compatible = "arm,pl011",
                                       reg = <u64 block_offset, u64 block_size>
                                       which is mapped at soc_base + block_offset
  * /product, /options, /defaults,  -> machine identity and the boot-manifest
    /chosen{,/manifest-properties,     tables that AppleImage4 (Kernelspace.cpp)
    /asmb}                             and the platform "mpo" policy code look up
                                       by path and panic over if missing

So the "SoC base" is the anchor the whole platform hangs off.  We pick the base
of QEMU virt's platform device window (the GIC) and express every device as an
offset from it.

Beyond the kernel's own pexpert code, the *drivers* published by iBoot's
platform kexts (com.apple.driver.AppleARMPlatform and
com.apple.driver.AppleVirtualPlatform) bind to nodes and match on their
properties, and IOKit services that never appear make their clients wait
forever.  The boot reaches the end of kext loading and then parks in
_processor_idle with no further output, which is that failure mode, so the
tree below carries the whole platform surface the authentic VMApple ADT
(kernel/DeviceTree.vma2macosap.adt) publishes, with this machine's own
addresses, phandles and devices:

    root            aliases, machine-timeouts, memory, vram, pram,
                    filesystems-props, buttons, port-virtual-1,
                    osenvironments, pmgr, chosen, defaults, product,
                    options, arm-io, cpus
    /arm-io         gic, uart0, pl031-rtc, pcie
    /chosen         the firmware policy properties plus the subnodes
                    memory-map, manifest-(object-)properties, iBoot,
                    secure-boot-hashes, boot-object-manifests,
                    dynamic-object-map, carveout-memory-map, lock-regs,
                    memory-report{,/zeroization-report}, asmb
    /product        util, usb-device

Nodes for devices this machine does not have are the job of the device models
(Trestle) or of the driver they belong to; see trestle/src/ and docs/design.md
for the mapping between the authentic AVP device offsets and the machines they
are emulated on.

Usage: build_adt.py [-o out.adt]   (default: build/gatehouse.adt)
"""

import argparse
import os
import struct
import sys

# ---------------------------------------------------------------------------
# The platform we are synthesizing.
#
# QEMU virt's MMIO lives at 0x0..0x8000000; picking the GIC as the SoC base
# keeps every device offset positive while staying a real address.
# ---------------------------------------------------------------------------
SOC_BASE = 0x08000000              # gPESoCBasePhys: QEMU virt GIC base
# /arm-io ranges: child 0 -> parent SOC_BASE, and the window is what makes a
# device address resolvable at all.  The platform resolves a child's "reg"
# through the parent chain (IODTResolveAddressCell(), iokit/Kernel/
# IODeviceTreeSupport.cpp): each level must find the address inside one of its
# "ranges" windows, and a node whose address falls outside every window ends up
# with no IODeviceMemory at all.  So every "reg" offset below has to be <
# SOC_SIZE, and for a bus whose window the guest sizes itself (see PCIe below)
# that constrains where the machine may put it.
SOC_SIZE = 0x38000000              # /arm-io ranges: 0x08000000..0x40000000

UART_PHYS = 0x09000000             # QEMU virt PL011
UART_SIZE = 0x1000

# QEMU virt's GICv3 (hw/arm/virt.c, memmap[]): the distributor and the
# redistributor frames.  pe_init_fiq() (pexpert/pexpert/arm64/pe_fiq.c) looks
# up "/arm-io/gic", requires a "reg" property of exactly 32 bytes
# ({GICD base, GICD size, GICR base, GICR size}, each u64 and each an offset
# from the SoC base) and maps both regions.  The GICv3 CPU interface is
# reachable through the ICC_* system registers, so the legacy GICC frame at
# 0x8010000 is not described.
GICD_PHYS = 0x08000000
GICD_SIZE = 0x10000
GICR_PHYS = 0x080A0000
# The redistributor region is a run of 128 KiB frames, one per CPU, and
# AppleARMGICv3.cpp:182 panics outright unless the size we publish is a
# multiple of 128K:
#
#     "Redistributor region size is not multiple of 128K."
#
# The reference platform's tree follows the same rule (32 cpus * 0x20000 =
# 0x400000), and so does QEMU, whose own region covers its 123 possible vCPUs
# (0xF60000).  We describe exactly the CPUs we publish -- cpus=1 in the boot
# arguments below -- so this is one frame.
GICR_SIZE = 0x20000

# The rest of QEMU virt's device window, from the machine's own DTB
# (-M virt,dumpdtb=...).  The authentic VMApple platform carries the same two
# devices; its other *paravirtual* devices (avp-rtc, avp-ctrr,
# avp-sealed-registers, pvpanic, aes, ...) have no QEMU backing and are left to
# Trestle, which emulates them on the real machine.
PL031_PHYS = 0x09010000            # PL031 RTC
PL031_SIZE = 0x1000

# QEMU virt's PCIe host bridge (hw/pci-host/gpex.c + hw/arm/virt.c).  This one
# *is* backed, and it is how the root disk attaches: XNU's storage stack is
# AppleVirtIOStorageDevice behind AppleVirtIOTransport, whose PCI transport
# matches the generic virtio vendor (AppleVirtIOBlock carries
# IOVirtIOPrimaryMatch = 0x00021af4, i.e. virtio device type 2 vendor 0x1af4),
# so a plain QEMU virtio-blk-pci is the right device.  The AVP's own root disk
# is the same concept dressed in Apple's PCI ids (106b:1a00), which this QEMU
# has no device for; see trestle/include/pcie.h for the whole path.
#
# The host bridge node below reproduces the authentic /arm-io/pcie (13
# properties) with this machine's addresses.  Its own register window is the
# ECAM, and "ranges" carries the CPU-side MMIO window:
#
#     reg            -> ECAM                  (QEMU: hw/arm/virt.c memmap)
#     ranges[0]      -> MMIO32 PCI 0x10000000 -> CPU 0x10000000, 0x2eff0000
#     interrupt-base -> first INTx GIC id      (QEMU: SPI 3..6 => ids 35..38)
#
# The ECAM is the low one (QEMU virt places it at 0x3f000000 with
# highmem-ecam=off: 16 MB, 16 buses) and that is what the machine is launched
# with.  It has to be low, and inside /arm-io "ranges": with the default
# 0x4010000000 ECAM the node's offset (0x4008000000) is far outside the
# 0x38000000-byte SoC window, IODTResolveAddressing() publishes an empty
# IODeviceMemory array, and AppleVirtualPlatformPCIE::start() panics with
#
#     AppleVirtualPlatformPCIE.cpp:34 Assertion failed: fEcamMM != NULL
#
# Low is also the faithful choice: the AVP's ECAM is physical 0x40000000.
PCIE_ECAM_PHYS = 0x3F000000         # QEMU virt: low ECAM (highmem-ecam=off)
PCIE_ECAM_SIZE = 0x01000000         # 16 MB: 16 buses of 1 MB
PCIE_MMIO_PCI_BASE = 0x10000000    # PCI side of the 32-bit MMIO window
PCIE_MMIO_CPU_BASE = 0x10000000    # ... and its CPU side (identity mapped)
PCIE_MMIO_SIZE = 0x2eff0000
# INTx pin 0 of device 0 is GIC id 35 (SPI 3); gpex swizzles (dev + pin) % 4.
# The AVP publishes 0x40 here because its first INTx is raw GIC id 0x40, which
# is exactly what QEMU's own vmapple wires (irqmap[VMAPPLE_PCIE] = 0x20 SPI).
PCIE_INTX_BASE = 35
# msi-frame-index is deliberately *not* published: the AVP's MSI frame is a
# GICv2m-shaped window at the GIC's third reg entry, and QEMU virt has no such
# device (its MSI goes through an ITS, which the guest's GIC driver -- built
# for the AVP -- does not drive).  Without the property the driver's
# AppleVirtualPlatformPCIEMSIController maps the GIC's first region instead, so
# MSI messages go nowhere; the virtio transport then uses INTx, exactly as it
# does on QEMU's own vmapple, which has no MSI frame either (its
# vmapple_compat_defaults exist because "there is no MSI(-X) support").
# QEMU virt's device tree advertises a PL061 at 0x09030000 with a gpio-keys
# child, but the machine does not instantiate the controller, so no node for it
# is published here: see the note above /arm-io in build().

TIMEBASE_HZ = 24000000             # architected timer frequency (QEMU virt)

# ---------------------------------------------------------------------------
# Phandles.  XNU resolves a node by its AAPL,phandle property only, so the
# numbering is ours to choose; we keep iBoot's from the authentic VMApple ADT
# so the two trees line up node for node.  Two of them are load-bearing:
# /defaults "serial-device" must be uart0's, and every "interrupt-parent" must
# be the gic's.
# ---------------------------------------------------------------------------
PHANDLE_BUTTONS = 0x02
PHANDLE_MACHINE_TIMEOUTS = 0x03
PHANDLE_CHOSEN = 0x04
PHANDLE_MANIFEST_PROPS = 0x05
PHANDLE_MANIFEST_OBJECT_PROPS = 0x06
PHANDLE_BOOT_OBJECT_MANIFESTS = 0x07
PHANDLE_SECURE_BOOT_HASHES = 0x08
PHANDLE_DYNAMIC_OBJECT_MAP = 0x09
PHANDLE_MEMORY_MAP = 0x0A
PHANDLE_CARVEOUT_MEMORY_MAP = 0x0B
PHANDLE_LOCK_REGS = 0x0C
PHANDLE_IBOOT = 0x0D
PHANDLE_MEMORY_REPORT = 0x0E
PHANDLE_ZEROIZATION_REPORT = 0x0F
PHANDLE_ASMB = 0x10
PHANDLE_OPTIONS = 0x11
PHANDLE_CPUS = 0x12
PHANDLE_CPU0 = 0x13
PHANDLE_ALIASES = 0x33
PHANDLE_MEMORY = 0x34
PHANDLE_PMGR = 0x35
PHANDLE_ARM_IO = 0x36
PHANDLE_UART0 = 0x38
PHANDLE_GIC = 0x39
PHANDLE_PL031_RTC = 0x3D
PHANDLE_PCIE = 0x3F
# Kept for the numbering, but not published by this machine: see the note above
# /arm-io in build().  Trestle's AVP machine does carry the node.
PHANDLE_PL061_BUTTONS = 0x40
PHANDLE_PRAM = 0x44
PHANDLE_VRAM = 0x45
PHANDLE_DEFAULTS = 0x46
PHANDLE_PRODUCT = 0x47
PHANDLE_PRODUCT_USB = 0x48
PHANDLE_PRODUCT_UTIL = 0x49
PHANDLE_FILESYSTEMS_PROPS = 0x4A
PHANDLE_PORT_VIRTUAL_1 = 0x4B
PHANDLE_OSENVIRONMENTS = 0x4C

# iBoot's panic region.  check_for_panic_log() (pexpert/arm/pe_init.c) reads it
# out of the ADT as
#
#     pram {
#         reg = <physical address, size>;
#     };
#     chosen {
#         embedded-panic-log-size = <max bytes of log to store>;
#     };
#
# and then does gPanicBase = ml_io_map_wcomb(reg[0], embedded-panic-log-size)
# followed by panic_info = gPanicBase.  Without it the kernel trips
# "pe_init.c: Assertion failed: panic_info" and the panic path cannot even
# print the panic text.  Gatehouse reserves these bytes inside the boot-data
# window below topOfKernelData (main.c checks the same constants).
KERN_IMG_PHYS = 0x81004000         # GH_KERN_PHYS_BASE + 0x1004000
PANIC_PHYS = KERN_IMG_PHYS + 0x05800000   # GH_PANIC_OFF (88 MiB: clear of an 81 MiB kernel collection)
PANIC_SIZE = 0x00080000            # 512 KiB

# /chosen dram-base/dram-size.  XNU's arm_init() reads both (mandatory: it
# panics without them) and stores them in gDramBase/gDramSize; the arm pmap then
# uses them to decide whether a physical page is cacheable DRAM or device
# memory (wimg_to_pte) and to seed pmap_first_pnum = dram-base >> 14.
#
# Must agree with the RAM QEMU is actually providing.  The machine runs with
# "highmem=off" and MEM=3G (see qemu/run.sh): with highmem on, QEMU's PCI bus
# also gains a 64-bit MMIO aperture at 0x8000000000, and UEFI puts the modern
# virtio BAR (BAR4, 64-bit prefetchable, 16 MB, where the modern transport
# lives) up there -- far outside the single 32-bit "ranges" window the
# reference platform describes for /arm-io/pcie.  The guest then has no
# IODeviceMemory for the transport and the root disk never appears as an
# IOMedia.  highmem=off removes that aperture, so UEFI falls back to placing
# 64-bit BARs inside the 32-bit window (which is where Apple's own devices
# live), at the cost of the RAM above 4G: 3G at 0x40000000..0x100000000.
RAM_BASE = 0x40000000
RAM_SIZE = 0xC0000000

# /chosen random-seed.  XNU's PE_get_random_seed() (pexpert/gen/pe_gen.c)
# looks up this property and panics ("no random seed") if it is absent, empty,
# or entirely zero; it copies min(size, request) bytes out and then zeroes the
# property in the tree.  The consumer (prng_random.c) requires the full 256-byte
# seed or it panics ("Expected 256 seed bytes from bootloader, but got N").
# Deterministic LCG output for reproducible runs -- dev only.
def _pseudo_seed(num_bytes=256, state=0x5EED_1234_5678_9ABC):
    out = bytearray()
    for _ in range(num_bytes):
        state = (state * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        out.append((state >> 33) & 0xFF)
    return bytes(out)

RANDOM_SEED = _pseudo_seed(256)


# ---------------------------------------------------------------------------
# ADT encoding
# ---------------------------------------------------------------------------
def s(text):
    """A string property value: XNU wants the NUL included."""
    return text.encode("ascii") + b"\0"


def u32(*values):
    return struct.pack("<%dI" % len(values), *values)


def u64(*values):
    return struct.pack("<%dQ" % len(values), *values)


class Node:
    def __init__(self, name, props=(), children=()):
        self.name = name
        self.props = list(props)
        self.children = list(children)


def node(name, *props, children=()):
    # Every node carries its name as a property: XNU's FindChild() matches
    # children by strcmp'ing the "name" property, not a name field.
    return Node(name, [("name", s(name))] + list(props), children)


def emit(n):
    out = struct.pack("<II", len(n.props), len(n.children))
    for name, value in n.props:
        raw = name.encode("ascii")
        if len(raw) > 31:
            raise SystemExit("property name too long: %s" % name)
        out += raw.ljust(32, b"\0")
        out += struct.pack("<I", len(value))
        out += value + b"\0" * (-len(value) % 4)
    for c in n.children:
        out += emit(c)
    return out


# /chosen/manifest-properties and /chosen/manifest-object-properties are fixed
# tables of reserved slots that Image4 fills in while it processes the boot
# manifest: 20 64-bit integers, 20 booleans and 10 fixed-size strings.  The
# authentic ADT ships every slot zeroed, so it is the table's *shape* that
# matters, not its contents.
def reserved_manifest_properties():
    props = []
    for i in range(20):
        props.append(("UnusedIntegerProperty%d" % i, u64(0)))
    for i in range(20):
        props.append(("UnusedBooleanProperty%d" % i, u32(0)))
    for i in range(10):
        props.append(("UnusedStringProperty%d" % i, b"\0" * 64))
    return props


# /chosen/memory-map is the same kind of table: iBoot reserves 16 slots that
# it fills in with physical ranges (byte offset, byte length) for the boot
# objects -- TrustCache, AuxKC, AuxKC-mach_header among them.  XNU's
# arm_vm_prot_init() (osfmk/arm64/arm_vm_init.c) asserts that the *node* exists
# and then reads each object out of it by name, so the reserved slots may stay
# zeroed; "kernel-only" is a boolean the same code reads.
def reserved_memory_map_properties():
    return [("MemoryMapReserved-%d" % i, u64(0, 0)) for i in range(16)]


# ---------------------------------------------------------------------------
# /chosen: the firmware policy properties.
#
# The machine-specific parts of /chosen (dram-base/dram-size, random-seed, the
# NVRAM store, the panic log size, the chip identity) are built in build()
# below; everything here is a firmware *policy* literal, copied property for
# property from the authentic VMApple ADT so that the security code
# (AppleImage4, AMFI, the platform "mpo" policy, the credential manager) sees
# exactly what iBoot publishes.  Properties iBoot frees after handing them to
# the kernel -- random-seed, bootp-response, firmware-version,
# host-os-information, cl4-entropy -- appear in the dump all-zero because the
# kernel has already consumed them; the same *length* is used here so the
# tree's shape is unchanged.
#
# One deliberate deviation: sepfw-load-at-boot is 0, not 1.  It tells the SEP
# manager to load SEP firmware during boot, and this machine has no SEP.
#
# A second: apfs-preboot-uuid is absent rather than zero-filled.  iBoot fills
# that property in with the boot volume group's Preboot volume UUID; this
# machine boots a plain, ungrouped APFS volume, so there is no Preboot volume.
# The zero-filled placeholder is worse than nothing -- AppleFileSystemDriver
# (the apfs kext) prefers apfs-preboot-uuid over boot-uuid whenever the
# property is present, and an all-zero value is not a parseable UUID, so the
# driver gives up and never publishes "boot-uuid-media", which is the resource
# IOKitBSDInit waits for.  Omitting it makes the driver fall through to
# boot-uuid, which names the root volume directly.
# ---------------------------------------------------------------------------
CHOSEN_FIRMWARE_PROPERTIES = [
    ("mix-n-match-prevention-status", u32(0)),
    ("max-env-var-data-size", u32(0)),
    ("software-bundle-version", s("syscfg/SBVr/0x10,zeroes/0x10")),
    ("repair-environment", u32(0)),
    ("repair-status", s("syscfg/rpcp")),
    ("software-behavior", s("syscfg/SwBh/0x10,zeroes/0x10")),
    ("effective-production-status-sep", u32(0)),
    ("disable-transport-rm", u32(0)),
    ("development-cert", u32(0)),
    ("mac-address-wifi0", s("macaddr/wifiaddr,syscfg/WMac/6")),
    ("marketing-hardware-behavior", s("syscfg/MkBH")),
    ("isp-horizon", u32(0)),
    ("max-env-partition", u32(0)),
    ("mac-address-ethernet1", s("macaddr/ethaddr1,syscfg/EMc2/6")),
    ("cs-system-policy", s("default")),
    ("system-trusted", u32(0)),
    ("display-rotation", u32(0)),
    ("amfi-allows-trust-cache-load", u32(0)),
    ("coverglass-color", s("syscfg/CLCG")),
    ("sidp-rom-manifest-hash", bytes(48)),
    ("sepfw-load-at-boot", u32(0)),
    ("enable-sep-rm", u32(0)),
    ("cryptex1-certificate-format", s("x509")),
    ("dram-vendor-id", u32(0)),
    ("display-boot-rotation", u32(0)),
    ("protected-data-access", u32(1)),
    ("secureboot-key-scheme", s("rsa4096")),
    ("allow-whitelist-disable", u32(1)),
    ("debug-board-revision", u32(0)),
    ("certificate-security-mode", u32(0)),
    ("host-os-information", bytes(128)),
    ("disable-av-content-protection", u32(0)),
    ("dram-vendor", bytes(16)),
    ("mac-address-bluetooth0", s("macaddr/btaddr,syscfg/BMac/6")),
    ("production-cert", u32(0)),
    ("cryptex1-key-scheme", s("rsa4096")),
    ("non-apple-or-untrusted-code", u32(1)),
    ("ephemeral-storage", u32(0)),
    ("mac-address-ethernet0", s("macaddr/ethaddr,syscfg/EMac/6")),
    ("debug-enabled", u32(0)),
    ("consistent-debug-root", u64(0)),
    ("enclosure-material", s("syscfg/EnMt")),
    ("effective-production-status-ap", u32(0)),
    ("marketing-software-behavior", s("syscfg/MkBS")),
    ("security-downgradable", u32(1)),
    ("bootp-response", bytes(300)),
    ("image4-cert-type", u32(0)),
    ("backing-glass-material", s("syscfg/BGMt")),
    ("cl4-entropy", bytes(192)),
    ("darwinos-security-environment", u32(0)),
    ("firmware-version", bytes(256)),
    ("display-scale", u32(0)),
    ("effective-security-mode-sep", u32(0)),
    ("certificate-production-status", u32(0)),
    # apfs-preboot-uuid is deliberately absent; see the note on the chosen
    # node below (the machine has no Preboot volume, and a present-but-zero
    # placeholder makes the apfs kext ignore boot-uuid).
    ("darwinos-userspace-reboot", u32(0)),
    ("allowed-boot-args", s("trace,trace_wake,kperf,-x,-v,trm_enabled,trace_typefilter,nox86exec")),
    ("secureboot-certificate-format", s("x509")),
    ("csr-allow-device-configuration", u32(0)),
    ("recovery-snag-key-pressed", u32(0)),
    ("#address-cells", u32(2)),
    ("repair-history", s("syscfg/RCHL")),
    ("enable-user-rm", u32(0)),
    ("cover-glass-material", s("syscfg/CGMt")),
    ("max-env-var-name-size", u32(0)),
    ("osenvironment", bytes(32)),
    ("unrestricted-subsystem-root", u32(0)),
    ("use-recovery-securityd", u32(0)),
    ("amfi-exec-req-tc", u32(0)),
    ("disable-accessory-firmware", u32(0)),
    ("boot-manifest-hash", bytes(48)),
    ("display-corner-radius", u32(0)),
    ("boot-type", b"local" + bytes(7)),
    ("board-id", u32(0)),
    ("housing-color", s("syscfg/CLHS")),
    ("backing-color", s("syscfg/CLBG")),
    ("effective-security-mode-ap", u32(0)),
]

# The same properties minus the ones built into the tree above, which are the
# machine's identity rather than firmware policy.
CHOSEN_IDENTITY_PROPERTIES = [
    # Chip / secure-boot identity, copied from the authentic /chosen.
    # AppleImage4 reads "crypto-hash-method" and maps "sha1"/"sha2-384"; if the
    # property is absent the value is empty and it panics with "non-sensical
    # crypto hash method".
    ("unique-chip-id", u64(0)),
    ("secure-boot", u32(0)),
    ("chip-id", u32(0)),
    ("boot-nonce", u64(0)),
    ("die-id", u64(0)),
    ("unique-device-id", bytes(16)),
    ("gid-aes-key", u32(0)),
    ("uid-aes-key", u32(0)),
    ("image4-supported", b""),
    ("allow-ap-nonce-retrieval", b""),
]


# ---------------------------------------------------------------------------
# NVRAM.
#
# XNU's NVRAM store lives in the /chosen property "nvram-proxy-data" with its
# size in "nvram-total-size", and the factory in iokit/Kernel/IONVRAM.cpp
# (XNU 27) inspects the first bytes to pick a handler:
#
#     ldr  w8,  [data]         ; first four bytes
#     cmp  w8,  #0x4e565633    ; store magic
#     ldrb w8,  [data, 0xe]
#     cmp  w8,  #1             ; format version
#
# A match builds IONVRAMV3Handler::create(owner, data, size) *with* the image;
# anything else builds IONVRAMCHRPHandler::create(owner, NULL, size) with no
# image at all, which leaves the handler uninitialised and faults later.  The
# store therefore has to be a V3 image.
#
# IONVRAMV3Handler::init() in turn requires these /chosen properties, all as
# 4-byte OSData, and fails silently (line 1688) if any is missing:
#
#     nvram-bank-size, nvram-bank-count, nvram-current-bank, nvram-raw
#
# "nvram-raw" is a flag: [handler 0x2c] = (value != 0).  "nvram-bank-size" is
# also the size that create() is handed.
#
# The V3 parser (IONVRAMV3Handler, reached from create) reads a 0x18-byte
# header and requires size >= 0x18, header[4] == size and header[0xe] == 1:
#
#     struct nvram_v3_header {            // 0x18 bytes
#         uint32_t magic;                 // 0x4e565633
#         uint32_t size;                  // total image size
#         uint32_t region_offset;         // -> handler field 0x30
#         uint8_t  reserved[2];           // 0x0c, 0x0d
#         uint8_t  version;               // 0x0e == 1
#         uint8_t  reserved2;
#         uint32_t field_10;              // -> handler field 0x4c
#         uint32_t data_end;              // -> handler field 0x48 (data_end - 0x18)
#     };
#
# On a real machine iBoot writes the live image here.  Producing it is the job
# of the platform NVRAM device model (Trestle; see trestle/src/nvram.c); this
# is the bring-up stand-in: an empty but well-formed V3 image.
# ---------------------------------------------------------------------------
NVRAM_SIZE = 8192               # the store size iBoot uses on Apple Silicon
NVRAM_V3_MAGIC = 0x4E565633


def _u32(value):
    return value.to_bytes(4, "little")


def nvram_proxy_data(size=NVRAM_SIZE):
    image = bytearray(size)
    image[0x00:0x04] = _u32(NVRAM_V3_MAGIC)
    image[0x04:0x08] = _u32(size)               # total image size
    image[0x08:0x0C] = _u32(0)                  # region offset
    image[0x0E] = 1                             # format version
    image[0x10:0x14] = _u32(0)
    image[0x14:0x18] = _u32(size)               # end of data
    return bytes(image)


# ---------------------------------------------------------------------------
# The tree itself.  This is the "emulated Apple platform": the interface
# between Gatehouse and XNU, and the only thing that has to change to move to a
# different machine.
# ---------------------------------------------------------------------------
def build():
    # ---------------------------------------------------------------------
    # /arm-io: the SoC's device window.
    # ---------------------------------------------------------------------
    uart = node(
        "uart0",
        ("compatible", s("arm,pl011")),
        # The property is Apple's "AAPL,phandle": SecureDTFindNodeWithPhandle()
        # (pexpert/gen/device_tree.c) searches for exactly that name, and
        # pe_serial.c panics with "Unable to find a devicetree node with
        # phandle %x" if it is missing.  A plain "phandle" is an FDT-ism and
        # is invisible to XNU.
        ("AAPL,phandle", u32(PHANDLE_UART0)),
        # reg is <block_offset, block_size>, relative to the SoC base
        # (pe_serial.c: ml_io_map(soc_base_phys + reg->block_offset, ...)).
        ("reg", u64(UART_PHYS - SOC_BASE, UART_SIZE)),
    )

    # pe_init_fiq() walks the GICR frames at 0x20000 stride looking for the
    # frame whose GICR_TYPER affinity matches MPIDR_EL1 & 0xffff, so the
    # region has to cover CPU 0's frame (0x080A0000) with room to spare.
    #
    # The "interrupt-controller"/"device_type"/"#interrupt-cells" properties
    # are what Apple's own interrupt-controller driver (AppleARMGIC on Apple
    # Silicon, gic,vmappl1 on the AVP) matches on; without them IOKit never
    # publishes an IOInterruptController and every client of
    # IOService::registerInterrupt waits for it.  "arm,gic-v3" is kept in the
    # compatible list for iBoot-compatible matchers.
    gic = node(
        "gic",
        ("compatible", s("gic,vmappl1") + s("ARM,gicv3") + s("arm,gic-v3")),
        ("interrupt-controller", s("master")),
        ("#interrupt-cells", u32(2)),
        ("#address-cells", u32(0)),
        ("device_type", s("interrupt-controller")),
        ("AAPL,phandle", u32(PHANDLE_GIC)),
        ("reg", u64(GICD_PHYS - SOC_BASE, GICD_SIZE,
                    GICR_PHYS - SOC_BASE, GICR_SIZE)),
    )

    # The RTC.  QEMU virt has a real PL031; the authentic AVP carries both
    # this node and its own paravirtual "avp-rtc", and AppleVirtualPlatform
    # registers a driver for each (ApplePL031RTC, AppleVirtualPlatformRTC).
    # The PL031 has no interrupt in the authentic tree, so none is described.
    pl031_rtc = node(
        "pl031-rtc",
        ("compatible", s("ARM,pl031")),
        ("AAPL,phandle", u32(PHANDLE_PL031_RTC)),
        ("reg", u64(PL031_PHYS - SOC_BASE, PL031_SIZE)),
    )

    # There is no PL061 button controller here.
    #
    # On the AVP the buttons hang off a PL061 GPIO controller with
    # role = "VMA1_BUTTONS", and QEMU's *generated* device tree still advertises
    # one ("pl061@9030000" with a gpio-keys child) -- but the machine never
    # instantiates it: it is not a user-creatable device, and "info mtree"
    # shows nothing between pl031@0x09010000 and acpi-ged@0x09080000.  A
    # window with no device behind it takes a synchronous external abort the
    # first time it is touched, and something does touch it: the AVP's GPIO
    # driver binds to this node and writes GPIOIEV/GPIOIE (0x40c/0x410) when it
    # starts.  XNU routes a kernel external abort to its
    # implementation-specific-error handler, whose fallback (no platform
    # handler is registered yet) reads IMPDEF syndrome registers that QEMU
    # leaves unallocated, so the abort surfaces as:
    #
    #     panic(cpu 0 caller 0xfffffe000a0899e8): Undefined kernel instruction:
    #       pc=0xfffffe000a828b24 instr=d53ef008 @sleh.c:1930
    #
    # A node whose device no machine can back is worse than no node, so this
    # description leaves it out, the same way it leaves out avp-rtc, avp-ctrr,
    # avp-sealed-registers and pvpanic.  Trestle's AVP machine (the
    # real-hardware path) still carries it, with the reference platform's
    # 0x10060000 window and SPI 5 (GIC id 0x25).
    #
    # The PCIe host bridge is the opposite case: QEMU virt does back one, the
    # AVP driver matches it through "pcie,vmapple1", and the root disk is
    # behind it, so it is published.  What does not exist here is the MSI
    # frame, which is why msi-frame-index is absent (see PCIE_INTX_BASE above);
    # INTx and the ECAM are ordinary GPEX, so the only device that has to work
    # over INTx is the virtio transport, which is what QEMU's own vmapple does
    # too.
    pcie = node(
        "pcie",
        ("compatible", s("pcie,vmapple1")),
        ("device_type", s("pci")),
        ("AAPL,phandle", u32(PHANDLE_PCIE)),
        # A PCI child address is <phys.hi phys.mid phys.lo>; the AVP publishes
        # 3 address cells and 2 size cells, and the bridge is a standard GPEX.
        ("#address-cells", u32(3)),
        ("#size-cells", u32(2)),
        # The reference platform has nine root ports, so its bus range is 0..8;
        # QEMU virt exposes a single bus, and a config read for an absent bus
        # returns all ones, so the same range is both faithful and harmless.
        ("bus-range", u32(0, 8)),
        ("dev-range", u32(0, 0xFF)),
        # reg is <offset, size> from the SoC base, the same convention as the
        # GIC and uart nodes; this machine puts the ECAM below 4 GB so that it
        # lands inside /arm-io "ranges" (see PCIE_ECAM_PHYS above).
        ("reg", u64(PCIE_ECAM_PHYS - SOC_BASE, PCIE_ECAM_SIZE)),
        # ranges is the standard <child address: 3, parent address: 2, size: 2>
        # cell group, in the ADT's native (little-endian) cell encoding.  The
        # CPU-side address is SoC-relative like every other address in this
        # table: the authentic AVP node says PCI 0x50000000 -> CPU 0x40000000
        # with the SoC base at 0x10000000, which is the identity mapping QEMU's
        # vmapple implements (and gets right against the same ADT).
        ("ranges", u32(0x02000000,
                       PCIE_MMIO_PCI_BASE, 0,
                       PCIE_MMIO_CPU_BASE - SOC_BASE, 0,
                       PCIE_MMIO_SIZE, 0)),
        # XNU's "interrupts" cells are raw GIC ids, so the INTx base is a raw
        # id too: SPI 3 is GIC id 35.
        ("interrupt-base", u32(PCIE_INTX_BASE)),
        ("device-interrupt-parent", u32(PHANDLE_GIC)),
    )

    arm_io = node(
        "arm-io",
        ("compatible", s("arm-io,vmapple1")),
        # iBoot publishes "vmapple2-io" here; pe_identify_machine() identifies
        # the machine from this node, and "vmapple" is the value the kernel
        # code paths this port was brought up against expect.
        ("device_type", s("vmapple")),
        ("soc-generation", s("VMApple2")),
        ("chip-revision", u32(0)),
        ("#address-cells", u32(2)),
        ("#size-cells", u32(2)),
        ("AAPL,phandle", u32(PHANDLE_ARM_IO)),
        # pe_arm_get_soc_base_phys() takes ranges[1] as the SoC base.  The
        # third cell (the window size) is what iBoot publishes; 0 for the base
        # means "no SoC" and disables the serial console entirely.
        ("ranges", u64(0, SOC_BASE, SOC_SIZE)),
        children=[gic, uart, pl031_rtc, pcie],
    )

    # ---------------------------------------------------------------------
    # /cpus.
    #
    # state and reg are the two properties ml_parse_cpu_topology() requires;
    # the rest are the CPU's identity and clock description, which
    # AppleARMCPU and AppleARMPMU read off the node.  "interrupts" is the
    # list iBoot publishes: GIC interrupt id 1 twice and GIC id 0x17 = PPI 7,
    # the PMU overflow interrupt (the machine's own DTB wires PPI 7 to
    # arm,armv8-pmuv3, so the ids are machine-neutral).
    #
    # The *-frequency values are the architected timer's frequency, which is
    # what the platform declares for the timebase on the AVP as well (24 MHz,
    # not the 1 GHz CNTFRQ_EL0 QEMU's max cpu reports -- XNU derives its
    # conversions from CNTFRQ_EL0 on arm64 and uses these for the clock
    # description it publishes to userland).
    # ---------------------------------------------------------------------
    cpu0 = node(
        "cpu0",
        ("state", s("running")),                # only "running" cpus are read
        ("compatible", s("ARM,v8")),
        ("interrupt-parent", u32(PHANDLE_GIC)),
        ("interrupts", u32(0x1, 0x1, 0x17, 0x1, 0x1, 0x1)),
        ("cpu-id", u32(0)),
        # reg is the *physical* cpu id (MPIDR_EL1 AFF1:AFF0); XNU requires it
        # (ml_parse_cpu_topology: ML_READPROP_MANDATORY) and later matches it
        # against "MRS MPIDR_EL1 & (MPIDR_AFF1_MASK|MPIDR_AFF0_MASK)", so it
        # must be the masked value the architected timer/cpu-local code sees,
        # not QEMU's raw register (which carries the RES1 bit 31).
        ("reg", u32(0)),
        ("device_type", s("cpu")),
        ("AAPL,phandle", u32(PHANDLE_CPU0)),
        ("timebase-frequency", u64(TIMEBASE_HZ)),
        ("clock-frequency", u64(TIMEBASE_HZ)),
        ("memory-frequency", u64(TIMEBASE_HZ)),
        ("peripheral-frequency", u64(TIMEBASE_HZ)),
        ("fixed-frequency", u64(TIMEBASE_HZ)),
        ("bus-frequency", u64(TIMEBASE_HZ)),
        ("cpu-version", u32(0)),
        # An empty property: XNU reads its presence, not its value.
        ("function-enable_core", b""),
    )

    cpus = node(
        "cpus",
        ("#address-cells", u32(1)),
        ("#size-cells", u32(0)),
        ("AAPL,phandle", u32(PHANDLE_CPUS)),
        children=[cpu0],
    )

    # ---------------------------------------------------------------------
    # /chosen: the boot contract.
    # ---------------------------------------------------------------------

    # arm_vm_prot_init() (osfmk/arm64/arm_vm_init.c) asserts that this node
    # exists: SecureDTLookupEntry(NULL, "chosen/memory-map", &mm) must return
    # kSuccess before it reads TrustCache / AuxKC out of it.  Those objects
    # and the 16 reserved slots iBoot leaves for boot objects are all
    # optional (their absence is handled), so the reserved slots stay zeroed.
    memory_map = node(
        "memory-map",
        ("AAPL,phandle", u32(PHANDLE_MEMORY_MAP)),
        ("kernel-only", s("true")),
        *reserved_memory_map_properties(),
    )

    # The boot-object tables AppleImage4 and the SFR manifest code look up by
    # path.  A real iBoot fills them in with the manifest hashes; an
    # unpopulated but present node is what their "not found" paths tolerate.
    manifest_object_props = node(
        "manifest-object-properties",
        ("AAPL,phandle", u32(PHANDLE_MANIFEST_OBJECT_PROPS)),
        *reserved_manifest_properties(),
    )
    boot_object_manifests = node(
        "boot-object-manifests",
        ("AAPL,phandle", u32(PHANDLE_BOOT_OBJECT_MANIFESTS)),
    )
    secure_boot_hashes = node(
        "secure-boot-hashes",
        ("AAPL,phandle", u32(PHANDLE_SECURE_BOOT_HASHES)),
    )
    dynamic_object_map = node(
        "dynamic-object-map",
        ("AAPL,phandle", u32(PHANDLE_DYNAMIC_OBJECT_MAP)),
    )
    carveout_memory_map = node(
        "carveout-memory-map",
        ("AAPL,phandle", u32(PHANDLE_CARVEOUT_MEMORY_MAP)),
    )
    lock_regs = node(
        "lock-regs",
        ("AAPL,phandle", u32(PHANDLE_LOCK_REGS)),
    )
    # iBoot's timing report: consumed by the boot-perf code, zeroed once read.
    iboot = node(
        "iBoot",
        ("AAPL,phandle", u32(PHANDLE_IBOOT)),
        ("load-kernel-start", u32(0)),
        ("debug-wait-start", u32(0)),
        ("start-time", u32(0)),
        ("populate-registry-time", u32(0)),
    )
    zeroization_report = node(
        "zeroization-report",
        ("AAPL,phandle", u32(PHANDLE_ZEROIZATION_REPORT)),
    )
    memory_report = node(
        "memory-report",
        ("AAPL,phandle", u32(PHANDLE_MEMORY_REPORT)),
        children=[zeroization_report],
    )

    # /chosen/asmb: an otherwise empty node.  Image4 publishes the
    # local-policy properties (lp-sip0, lp-stng, ...) into it at runtime.
    asmb = node(
        "asmb",
        ("AAPL,phandle", u32(PHANDLE_ASMB)),
    )

    manifest_props = node(
        "manifest-properties",
        ("AAPL,phandle", u32(PHANDLE_MANIFEST_PROPS)),
        *reserved_manifest_properties(),
    )

    chosen = node(
        "chosen",
        ("AAPL,phandle", u32(PHANDLE_CHOSEN)),
        ("boot-args", s("debug=0x14e -v -noprogress serial=1 cpus=1 kextlog=0xfff keepsyms=1 exe_boothash_salt=0")),
        # IOKitBSDInit() (IOKit/IOKitBSDInit.cpp) reads this to find the root
        # media: it takes the UUID string here (at most 37 bytes) and waits for
        # an IOMedia whose UUID matches it to publish the "boot-uuid-media"
        # resource -- the media the kernel mounts as /.  When no media ever
        # matches it writes "boot-picker-bringup-reason" to NVRAM and brings up
        # the boot picker, which is where a boot with no boot-uuid stops.  iBoot
        # sets this on a real machine; the authentic VMApple ADT template does
        # not carry it because the firmware adds it at boot, so this is one of
        # the machine-specific values.  It is the APFS *volume* UUID in the
        # bring-up root volume's superblock (vmapple-rootfs), 36 characters.
        ("boot-uuid", s("20ED2DC7-B9F5-4DD3-8EE9-C6EF9AD3AD5A")),
        # arm_init() panics unless both are present; u64, little-endian.
        ("dram-base", u64(RAM_BASE)),
        ("dram-size", u64(RAM_SIZE)),
        # PE_get_random_seed(): mandatory, non-empty, not all zeros.
        ("random-seed", RANDOM_SEED),
        # ml_unsafe_kernel_text_init() (osfmk/kern/machine_routines.c) reads
        # this from iBoot to decide whether the kernel text is protected by
        # CTRR.  Its absence leaves _unsafe_kernel_text_initialized false and
        # the next ml_unsafe_kernel_text() call trips the assert in that
        # function.  QEMU's virt machine has no CTRR at all (on vmapple it is
        # paravirtualised through /arm-io/avp-ctrr, which we do not provide),
        # so the truthful value is 0 = "CTRR will not be enabled" = the text
        # stays writable.
        ("kernel-ctrr-to-be-enabled", u32(0)),
        # check_for_panic_log() reads the size of the panic log from here.
        ("embedded-panic-log-size", u32(PANIC_SIZE)),
        # AppleImage4's hash method and the machine's identity.
        ("crypto-hash-method", s("sha2-384")),
        *CHOSEN_IDENTITY_PROPERTIES,
        # The NVRAM store.  The factory reads nvram-bank-size and passes it to
        # IONVRAMV3Handler::create() as the image size, so the bank geometry,
        # nvram-total-size and the image size all have to agree.
        ("nvram-total-size", u32(NVRAM_SIZE)),
        ("nvram-proxy-data", nvram_proxy_data()),
        ("nvram-bank-size", u32(NVRAM_SIZE)),
        ("nvram-bank-count", u32(1)),
        ("nvram-current-bank", u32(0)),
        # IONVRAMV3Handler::init() also requires "nvram-raw": it must be an
        # OSData, and its first word selects raw vs. structured interpretation
        # of the store ([obj+0x2c] = value != 0).  iBoot provides it.
        ("nvram-raw", u32(0)),
        *CHOSEN_FIRMWARE_PROPERTIES,
        children=[memory_map, manifest_props, manifest_object_props, asmb,
                  boot_object_manifests, secure_boot_hashes, dynamic_object_map,
                  carveout_memory_map, lock_regs, iboot, memory_report],
    )

    # /defaults: platform tuning.  pe_serial.c reads "serial-device" (the
    # uart0 phandle) and panics without it; the rest is copied from the
    # authentic ADT.
    defaults = node(
        "defaults",
        ("AAPL,phandle", u32(PHANDLE_DEFAULTS)),
        ("serial-device", u32(PHANDLE_UART0)),   # -> /arm-io/uart0
        ("vmm-present", u32(1)),
        ("force-sep-nonce", u32(1)),
        ("avp-encryption-version", u32(0)),
        ("kern.vm_compressor", u32(4)),
        ("ean-storage-present", b""),
        ("pmap-max-asids", u32(0x4000)),
        ("has-xart", u32(1)),
        ("no-effaceable-storage", b""),
        ("sleep-disabled", u32(1)),
    )

    # /product: the machine's identity, copied property-for-property from the
    # authentic VMApple ADT, plus the two subnodes iBoot publishes with it.
    #
    # "util" is the region descriptor table the platform's util-storage driver
    # (AppleVirtualPlatformUtilStorage) looks up by path; "usb-device"
    # describes the virtual USB device controller the AVP presents (NCM =
    # network-control-model Ethernet over USB).
    product_util = node(
        "util",
        ("AAPL,phandle", u32(PHANDLE_PRODUCT_UTIL)),
        ("reg", b""),
        ("low-level-fw-device-info", u32(1)),
        ("regions", bytes.fromhex(
            "01000000000000000000a000020000000000a0000000100003"
            "0000000000b0000000500007000000000000010010000004000"
            "0000010000100f04f0005000000000050010000500006000000"
            "0000a00100006000")),
        ("fw-regions", bytes.fromhex(
            "000000000000020000000200000020000000220000002000")),
    )

    product_usb = node(
        "usb-device",
        ("AAPL,phandle", u32(PHANDLE_PRODUCT_USB)),
        ("ncm-self-name-unit", u32(0)),
        ("ncm-interrupt-ep-disabled", u32(1)),
        ("ncm-control-ecid-mac", u32(1)),
        ("configuration-string", s("ncmAuxBringup")),
        ("product-string", s("macOS Virtual Machine")),
        # Apple's USB vendor id: this is the identity the VM presents to the
        # host, not a device the kernel drives.
        ("vendor-id", u32(0x5AC)),
    )

    product = node(
        "product",
        ("AAPL,phandle", u32(PHANDLE_PRODUCT)),
        ("has-virtualization", u32(1)),
        ("location-reminders", u32(0)),
        ("graphics-featureset-fallbacks", s("APPLE6:APPLE5:APPLE4:APPLE3:APPLE3v1:APPLE2:APPLE1:GLES2,0")),
        ("device-perf-memory-class", u32(0x10)),
        ("fdr-product-type", s("VirtualMac2,1")),
        ("has-applelpm", u32(0)),
        ("builtin-mics", u32(0)),
        ("artwork-device-subtype", u32(0)),
        ("allow-32bit-apps", u32(1)),
        ("compatible-device-fallback", s("iPad8,6")),
        ("app-macho-architecture", s("arm64")),
        ("product-description", s("virtual machine for ARM-v8.4 with Apple Silicon extensions")),
        ("chrome-identifier", s("0")),
        ("has-boot-chime", u32(0)),
        ("sub-product-type", s("VirtualMac2,1")),
        ("framebuffer-identifier", s("0")),
        ("sandman-support", u32(0)),
        ("atomic-firmware-update-support", u32(1)),
        ("RF-exposure-separation-distance", u32(5)),
        ("single-stage-boot", u32(1)),
        ("dali-mode", u32(0)),
        ("unique-model", s("VMA2MACOSAP")),
        ("graphics-featureset-class", s("APPLE7")),
        ("mobiledevice-min-ver", s("1853")),
        ("apple-guest-agent-port", u32(0x7b4da)),
        ("compatible-app-variant", s("MacFamily20,1")),
        ("ui-weather-quality", u32(0x64)),
        ("exclaves-enabled", u32(0)),
        ("artwork-dynamic-displaymode", s("0")),
        ("dual-iboot-support", u32(1)),
        ("has-exclaves", u32(0)),
        ("assistant", u32(0)),
        ("partition-style", s("macOS")),
        ("product-id", bytes.fromhex("23f17bc00dc6eab8162e14033bea91e057f61510")),
        ("product-name", s("Apple Virtual Machine 1")),
        ("udid-version", u32(2)),
        ("ephemeral-data-mode", u32(0)),
        ("lockdown-certtype", u32(0)),
        ("dictation", u32(0)),
        ("artwork-scale-factor", u32(2)),
        ("artwork-device-idiom", s("mac")),
        ("artwork-display-gamut", s("P3")),
        children=[product_util, product_usb],
    )

    # /options: an otherwise empty node; callers only test for its existence.
    options = node(
        "options",
        ("AAPL,phandle", u32(PHANDLE_OPTIONS)),
    )

    # ---------------------------------------------------------------------
    # The rest of the root: nodes the platform drivers bind to.
    # ---------------------------------------------------------------------

    # check_for_panic_log() (pexpert/arm/pe_init.c) looks up "pram" at the root
    # and takes reg[0] as the panic region's physical address.
    pram = node(
        "pram",
        ("device_type", s("pram")),
        ("AAPL,phandle", u32(PHANDLE_PRAM)),
        ("reg", u64(PANIC_PHYS, PANIC_SIZE)),
    )

    aliases = node(
        "aliases",
        ("AAPL,phandle", u32(PHANDLE_ALIASES)),
    )

    # The timeout scales XNU applies to locks and interrupt-masked sections.
    # Every scale is zero on the VMApple platform ("no scaling"), but the node
    # has to exist for the code that reads it.
    machine_timeouts = node(
        "machine-timeouts",
        ("AAPL,phandle", u32(PHANDLE_MACHINE_TIMEOUTS)),
        ("lock-scale", u32(0)),
        ("debug-ack-scale", u32(0)),
        ("lock-panic-scale", u32(0)),
        ("interrupt-masked-b-scale", u32(0)),
        ("interrupt-masked-scale", u32(0)),
        ("sched-preemption-disable-mode", u32(0)),
        ("gicr-wake-timeout-scale", u32(0)),
        ("sshot-interrupt-masked-scale", u32(0)),
        ("ticket-lock-scale", u32(0)),
        ("interrupt-masked-debug-mode", u32(0)),
    )

    # reg is zeroed in the authentic tree: the kernel takes the memory map from
    # boot_args, and these two nodes only mark the device types.
    memory = node(
        "memory",
        ("device_type", s("memory")),
        ("AAPL,phandle", u32(PHANDLE_MEMORY)),
        ("reg", u64(0)),
    )

    vram = node(
        "vram",
        ("device_type", s("vram")),
        ("AAPL,phandle", u32(PHANDLE_VRAM)),
        ("reg", u64(0, 0)),
    )

    # Filesystem policy: the inode/snapshot cache size and the fact that this
    # platform does not use APFS crypto.
    filesystems_props = node(
        "filesystems-props",
        ("AAPL,phandle", u32(PHANDLE_FILESYSTEMS_PROPS)),
        ("isc_size", u32(0x1F400000)),
        ("apfs-crypto-disabled", u32(1)),
    )

    buttons = node(
        "buttons",
        ("AAPL,phandle", u32(PHANDLE_BUTTONS)),
        ("aot-power", u32(1)),
    )

    # The virtual USB port the AVP exposes to its host.
    port_virtual_1 = node(
        "port-virtual-1",
        ("port-type", u32(1)),
        ("transports-supported", u32(2)),
        ("port-number", u32(1)),
        ("device_type", s("port-virtual")),
        ("AAPL,phandle", u32(PHANDLE_PORT_VIRTUAL_1)),
    )

    osenvironments = node(
        "osenvironments",
        ("AAPL,phandle", u32(PHANDLE_OSENVIRONMENTS)),
    )

    # /pmgr: the power manager.  XNU's platform code and ApplePSCI bind to it;
    # without it there is no root power domain, and AppleImage4 (which reads
    # the domain before it will evaluate the boot manifest) reports
    # "root power domain not yet available" and waits.
    pmgr = node(
        "pmgr",
        ("compatible", s("ARM,psci")),
        ("AAPL,phandle", u32(PHANDLE_PMGR)),
    )

    root = node(
        "device-tree",
        # The machine's identity.  pe_identify_machine() and the platform
        # expert read these at boot: the model, the target type, the
        # manufacturer and the serial/region numbers become the platform
        # expert's own properties (IOPlatformSerialNumber, hw.model, ...).
        # The target types are iBoot's own ("VMA2MACOS"/"VMA2MACOSAP"); the
        # machine-specific strings are Gatehouse's, because this is not an
        # Apple-serialised machine (iBoot fills these in from the syscfg
        # region on a real one).
        ("AAPL,phandle", u32(0x01)),
        ("device_type", s("bootrom")),
        ("device-tree-tag", s("EmbeddedDeviceTrees-12661.1.5")),
        ("manufacturer", s("Apple Inc.")),
        ("model", s("VirtualMac2,1")),
        ("model-config", s("HackintARM")),
        ("model-number", s("HACKINTARM1")),
        ("target-type", s("VMA2MACOS")),
        ("target-sub-type", s("VMA2MACOSAP")),
        ("serial-number", s("HACKINTARM0001")),
        ("mlb-serial-number", s("HACKINTARMMLB0001")),
        ("config-number", s("HACKINTARM0001")),
        ("regulatory-model-number", s("HACKINTARM1")),
        ("region-info", s("LL/A")),
        ("country-of-origin", s("US")),
        ("secure-root-prefix", s("md")),
        ("platform-name", bytes(32)),
        ("clock-frequency", u32(0)),
        ("time-stamp", s("Thu Jan 1 00:00:00 UTC 2026")),
        # AppleVirtualPlatformARMPE (com.apple.driver.AppleVirtualPlatform)
        # matches its provider with IONameMatch = "AppleVirtualPlatformARM",
        # and IODTCompareNubName tests the node's compatible as well as its
        # name.  The platform nub is named from compatible[0]; a machine with
        # no matching platform expert ends up in IOPanicPlatform and panics
        # with that name ("Unable to find driver for this platform").
        ("compatible", s("AppleVirtualPlatformARM")
         + s("VMA2MACOSAP")
         + s("VirtualMac2,1")),
        ("#address-cells", u32(2)),
        ("#size-cells", u32(2)),
        children=[chosen, defaults, product, options, arm_io, cpus, pram,
                  aliases, machine_timeouts, memory, vram, filesystems_props,
                  buttons, port_virtual_1, osenvironments, pmgr],
    )
    return root


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()

    root = build()
    blob = emit(root)

    out = args.output
    if out is None:
        here = os.path.dirname(os.path.abspath(__file__))
        out = os.path.join(here, "..", "..", "build", "gatehouse.adt")
    with open(out, "wb") as f:
        f.write(blob)
    print("wrote %s (%d bytes)" % (os.path.relpath(out), len(blob)), file=sys.stderr)


if __name__ == "__main__":
    main()
