#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors
#
# kc_patch.py - apply documented bring-up workarounds to a kernel collection.
#
# Gatehouse loads the kernel collection (MH_FILESET) 1:1 and leaves its chained
# fixups to XNU, so the shipped image is otherwise used exactly as Apple built
# it.  A small number of *environment* workarounds are nevertheless needed to
# bring the reference kernel up on machines Apple never shipped it for.  They are
# applied here, to the *copy* that qemu/run.sh stages into the ESP, so kernel/
# stays pristine and the workarounds are visible and reviewable in one place.
#
# Every patch names the unslid virtual address of the instruction it replaces,
# the exact bytes expected there and the replacement bytes.  A mismatch is a
# hard error, so a patch can never silently land on the wrong kernel build.
#
# Patches
# -------
#
# IOPCIDevice-extendedFindPCICapability-reference-search
#   VA 0xfffffe00095121c0  (com.apple.iokit.IOPCIFamily)
#     b40002c9  cbz x9, <config-space search>  ->  14000016  b <config-space search>
#
#   macOS 27's IOPCIDevice::extendedFindPCICapability() has a fast path that
#   answers capability lookups from a per-device capability dictionary built by
#   IOPCIBridge::constructCapabilitiesDict().  For a device that exposes several
#   *vendor-specific* capabilities -- which is every virtio-pci device, and they
#   all carry capability ID 0x09 (common/notify/isr/device/pci-cfg) -- that
#   dictionary collapses to a single entry, so the fast path hands back the
#   first vendor capability no matter what offset it is given.
#
#   AppleVirtIOPCITransport::start() walks a device's vendor capabilities with
#   extendedFindPCICapability(9, &offset), looping until the call reports that
#   none is left.  With the fast path in play it never does, so start() spins
#   forever: no AppleVirtIOTransport / AppleVirtIOBlockStorageDevice is ever
#   registered, no IOMedia appears and the boot parks at
#   "Waiting on ... (IOBSD, boot-uuid-media)".
#
#   The patched instruction is the one that selects the fast path (it branches
#   over the reference config-space search when the dictionary is present).
#   Making it an unconditional branch sends every lookup through the search
#   Apple itself uses when no dictionary exists -- the one that walks the PCI
#   capability list in config space, which iterates and terminates correctly.
#
import argparse
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
MH_FILESET = 0xC
LC_SEGMENT_64 = 0x19

PATCHES = [
    dict(
        name="IOPCIDevice-extendedFindPCICapability-reference-search",
        va=0xFFFFFE00095121C0,
        old=0xB40002C9,
        new=0x14000016,
    ),
]


def parse_segments(data):
    magic, _, _, filetype, ncmds, _, _, _ = struct.unpack_from("<IIIIIIII", data, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit("error: not a 64-bit Mach-O image (magic %#010x)" % magic)
    if filetype != MH_FILESET:
        raise SystemExit("error: not a kernel collection (filetype %#x)" % filetype)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].split(b"\0")[0].decode("utf8", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            if vmsize:
                segs.append((vmaddr, vmsize, fileoff, filesize, name))
        off += cmdsize
    return segs


def va_to_file(segs, va):
    for vmaddr, vmsize, fileoff, filesize, name in segs:
        if vmaddr <= va < vmaddr + vmsize:
            return fileoff + (va - vmaddr), name
    return None, None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kernel", help="kernel collection to patch (modified in place)")
    ap.add_argument("-n", "--dry-run", action="store_true",
                    help="verify only; do not write")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    with open(args.kernel, "rb") as f:
        data = bytearray(f.read())
    if len(data) < 32:
        raise SystemExit("error: %s is too small to be a kernel collection" % args.kernel)
    segs = parse_segments(data)
    if not args.quiet:
        print("kernel collection: %s (%d bytes, %d segments)"
              % (args.kernel, len(data), len(segs)))

    changed = False
    for p in PATCHES:
        foff, segname = va_to_file(segs, p["va"])
        if foff is None:
            raise SystemExit("error: %s: VA %#x is not mapped" % (p["name"], p["va"]))
        have = struct.unpack_from("<I", data, foff)[0]
        if have == p["new"]:
            if not args.quiet:
                print("  %-58s VA %#x  already applied  [%s]"
                      % (p["name"], p["va"], segname))
            continue
        if have != p["old"]:
            raise SystemExit(
                "error: %s: at VA %#x (file %#x, %s) expected %#010x, found %#010x; "
                "this is not the kernel this patch was written for"
                % (p["name"], p["va"], foff, segname, p["old"], have))
        if not args.quiet:
            print("  %-58s VA %#x  %#010x -> %#010x  [%s]"
                  % (p["name"], p["va"], p["old"], p["new"], segname))
        struct.pack_into("<I", data, foff, p["new"])
        changed = True

    if changed and not args.dry_run:
        with open(args.kernel, "wb") as f:
            f.write(data)
        if not args.quiet:
            print("patched %s" % args.kernel)
    elif not args.quiet:
        print("up to date; nothing to write" if args.dry_run else "no changes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
