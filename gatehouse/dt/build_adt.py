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

What XNU's arm64 platform code looks for (pexpert/arm/), and therefore what
this tree has to contain:

  * root, name = "device-tree"      -> model, target-type        (pe_init.c)
  * a node named "arm-io"           -> ranges, whose second u64 is
                                       gPESoCBasePhys; 0 means "no SoC" and
                                       disables the serial console entirely
                                       (pe_identify_machine.c)
  * /cpus                           -> children with state = "running" and the
                                       *-frequency properties (pe_identify_machine.c)
  * a node named "defaults"         -> serial-device = <phandle>
                                       (pe_serial.c; missing -> panic)
  * the serial node                 -> AAPL,phandle, compatible = "arm,pl011",
                                       reg = <u64 block_offset, u64 block_size>
                                       which is mapped at soc_base + block_offset
  * /product, /options, /defaults,  -> machine identity and the boot-manifest
    /chosen{,/manifest-properties,     tables that AppleImage4 (Kernelspace.cpp)
    /asmb}                             and the platform "mpo" policy code look up
                                       by path and panic over if missing; copied
                                       from the authentic VMApple ADT

So the "SoC base" is the anchor the whole platform hangs off.  We pick the base
of QEMU virt's platform device window (the GIC) and express every device as an
offset from it.

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
UART_PHYS = 0x09000000             # QEMU virt PL011
UART_SIZE = 0x1000
PHANDLE_UART0 = 1

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
GICR_SIZE = 0x0F6000
PHANDLE_GIC = 2

TIMEBASE_HZ = 24000000             # architected timer frequency (QEMU virt)

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
# Must agree with the RAM QEMU is actually providing (MEM=4G in run.sh).
RAM_BASE = 0x40000000
RAM_SIZE = 0x100000000

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


# /chosen/manifest-properties is a fixed table of reserved slots that Image4
# fills in while it processes the boot manifest: 20 64-bit integers, 20
# booleans and 10 fixed-size strings.  The authentic ADT ships every slot
# zeroed, so it is the table's *shape* that matters, not its contents.
def reserved_manifest_properties():
    props = []
    for i in range(20):
        props.append(("UnusedIntegerProperty%d" % i, u64(0)))
    for i in range(20):
        props.append(("UnusedBooleanProperty%d" % i, u32(0)))
    for i in range(10):
        props.append(("UnusedStringProperty%d" % i, b"\0" * 64))
    return props


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
    gic = node(
        "gic",
        ("compatible", s("arm,gic-v3")),
        ("AAPL,phandle", u32(PHANDLE_GIC)),
        ("reg", u64(GICD_PHYS - SOC_BASE, GICD_SIZE,
                    GICR_PHYS - SOC_BASE, GICR_SIZE)),
    )

    arm_io = node(
        "arm-io",
        ("device_type", s("vmapple")),
        # pe_arm_get_soc_base_phys() takes ranges[1] as the SoC base.
        ("ranges", u64(0, SOC_BASE)),
        children=[gic, uart],
    )

    cpu0 = node(
        "cpu0",
        ("state", s("running")),           # only "running" cpus are read
        # reg is the *physical* cpu id (MPIDR_EL1 AFF1:AFF0); XNU requires it
        # (ml_parse_cpu_topology: ML_READPROP_MANDATORY) and later matches it
        # against "MRS MPIDR_EL1 & (MPIDR_AFF1_MASK|MPIDR_AFF0_MASK)", so it
        # must be the masked value the architected timer/cpu-local code sees,
        # not QEMU's raw register (which carries the RES1 bit 31).
        ("reg", u32(0)),
        ("timebase-frequency", u32(TIMEBASE_HZ)),
        ("clock-frequency", u32(TIMEBASE_HZ)),
    )

    cpus = node("cpus", children=[cpu0])

    # arm_vm_prot_init() (osfmk/arm64/arm_vm_init.c) asserts that this node
    # exists: SecureDTLookupEntry(NULL, "chosen/memory-map", &mm) must return
    # kSuccess before it reads TrustCache / AuxKC out of it.  TrustCache,
    # AuxKC and AuxKC-mach_header are all optional (their absence is handled),
    # so an empty node satisfies the assert.
    memory_map = node("memory-map")

    # ---------------------------------------------------------------------
    # AppleImage4 (Kernelspace.cpp) and the platform-expert "mpo" policy code
    # look these up by path and panic if they are absent:
    #
    #     panic: failed to get chosen node
    #     panic: failed to get options node
    #     panic: failed to get defaults node
    #     panic: failed to get product node
    #     panic: failed to get manifest properties
    #
    # and Image4 additionally *populates* /chosen, /product, /defaults,
    # /chosen/manifest-properties and /chosen/asmb ("unable to setup ... node").
    # The contents below mirror the authentic VMApple ADT
    # (kernel/DeviceTree.vma2macosap.adt); only the phandle numbers differ,
    # because we number our own devices from 1.
    # ---------------------------------------------------------------------

    # /options: an otherwise empty node; callers only test for its existence.
    options = node(
        "options",
        ("AAPL,phandle", u32(0x11)),
    )

    # /chosen/asmb: likewise.  Image4 publishes the local-policy properties
    # (lp-sip0, lp-stng, ...) into it at runtime.
    asmb = node(
        "asmb",
        ("AAPL,phandle", u32(0x10)),
    )

    manifest_props = node(
        "manifest-properties",
        ("AAPL,phandle", u32(0x5)),
        *reserved_manifest_properties(),
    )

    chosen = node(
        "chosen",
        ("AAPL,phandle", u32(0x4)),
        ("boot-args", s("debug=0x14e -v -noprogress serial=1 cpus=1 kextlog=0xfff keepsyms=1 exe_boothash_salt=0")),
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
        children=[memory_map, manifest_props, asmb],
    )

    defaults = node(
        "defaults",
        ("AAPL,phandle", u32(0x46)),
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
    # authentic VMApple ADT.
    product = node(
        "product",
        ("AAPL,phandle", u32(0x47)),
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
    )

    # check_for_panic_log() (pexpert/arm/pe_init.c) looks up "pram" at the root
    # and takes reg[0] as the panic region's physical address.
    pram = node(
        "pram",
        ("reg", u64(PANIC_PHYS, PANIC_SIZE)),
    )

    root = node(
        "device-tree",
        ("model", s("Gatehouse virtual platform")),
        ("target-type", s("vmapple")),
        ("compatible", s("Apple,vmapple")),
        ("#address-cells", u32(2)),
        ("#size-cells", u32(2)),
        children=[chosen, defaults, product, options, arm_io, cpus, pram],
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
