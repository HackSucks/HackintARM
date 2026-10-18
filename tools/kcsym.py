#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
tools/kcsym.py - name addresses in a prelinked kernel collection.

A kernel collection (`kernelcache.release.*.kc`) is an MH_FILESET Mach-O: a
top-level header followed by one LC_FILESET_ENTRY (0x80000035) per kext, each
carrying { vmaddr, fileoff, size, entry_id }.  The Mach-O embedded at `fileoff`
is a normal kext Mach-O whose segments already use the *collection*'s linked
addresses, and - crucially - whose LC_SYMTAB is intact.  The collection's own
__TEXT_EXEC covers the kernel plus every kext's executable text, so a single
symbol table lookup answers "which kext and which function is 0xfffffe...?".

Unlike tools/symmap.py (which transfers names from a development kernel into the
stripped release kernel by function order), this reads the names the collection
itself carries, so the result is exact and covers kext code as well as the
kernel.

Usage:
    kcsym.py 0xfffffe0008a9eec0 0xfffffe0009523344
    kcsym.py --disasm 0x40 0xfffffe0008a9eec0
    kcsym.py --kext com.apple.driver.AppleVirtIO --symbols start
"""

import argparse
import bisect
import os
import struct
import subprocess
import sys
import tempfile

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_FILESET_ENTRY = 0x80000035
N_UNDF = 0x0
N_TYPE = 0x0E
N_SECT = 0x0E

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_KC = os.path.join(REPO, "kernel", "kernelcache.release.vma2.kc")

OBJDUMP = "aarch64-linux-gnu-objdump"


class Kext:
    """One LC_FILESET_ENTRY: its segments, its symbol table and its sections."""

    __slots__ = ("entry_id", "vmaddr", "fileoff", "size", "segments", "symtab",
                 "data", "_syms", "_vals")

    def __init__(self, data, entry_id, vmaddr, fileoff, size):
        self.data = data
        self.entry_id = entry_id
        self.vmaddr = vmaddr
        self.fileoff = fileoff
        self.size = size
        self.segments = []          # (name, vmaddr, vmsize, fileoff, filesize)
        self.symtab = None          # (symoff, nsyms, stroff, strsize)
        self._parse()

    def _parse(self):
        d = self.data
        base = self.fileoff
        ncmds, = struct.unpack_from("<I", d, base + 16)
        off = base + 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            if cmd == LC_SEGMENT_64:
                name = d[off + 8:off + 24].split(b"\0")[0].decode()
                seg = struct.unpack_from("<QQQQ", d, off + 24)
                self.segments.append((name,) + seg)
            elif cmd == LC_SYMTAB:
                self.symtab = struct.unpack_from("<IIII", d, off + 8)
            off += cmdsize
        self._syms = None
        self._vals = None

    # Only executable segments may name a code address.  A kext's __LINKEDIT
    # (and __DATA_CONST) can span most of the collection, so matching any
    # segment would let one kext claim another's addresses.
    CODE_SEGMENTS = ("__TEXT", "__TEXT_EXEC", "__PRELINK_TEXT")

    def contains(self, addr):
        for name, vm, vs, _fo, _fs in self.segments:
            if name in self.CODE_SEGMENTS and vm <= addr < vm + vs:
                return name
        return None

    def symbols(self):
        """Ordered [(addr, name)] from the collection's shared symbol table."""
        if self._syms is not None:
            return self._syms
        d = self.data
        out = []
        if self.symtab:
            symoff, nsyms, stroff, strsize = self.symtab
            strtab = d[stroff:stroff + strsize]
            for i in range(nsyms):
                n_strx, n_type, _n_sect, _n_desc, n_value = \
                    struct.unpack_from("<IBBHQ", d, symoff + i * 16)
                if (n_type & N_TYPE) == N_UNDF:
                    continue
                end = strtab.find(b"\0", n_strx)
                if end < 0:
                    continue
                name = strtab[n_strx:end].decode("utf-8", "replace")
                if name:
                    out.append((n_value, name))
        out.sort()
        self._syms = out
        self._vals = [v for v, _ in out]
        return out

    def resolve(self, addr):
        """(segment, name, offset) for a code address inside this kext."""
        seg = self.contains(addr)
        if seg is None:
            return None
        syms = self.symbols()
        if not syms:
            return seg, None, 0
        j = bisect.bisect_right(self._vals, addr) - 1
        if j < 0:
            return seg, None, 0
        return seg, syms[j][1], addr - syms[j][0]


def demangle(name):
    """Best-effort Itanium demangle, falling back to the raw name."""
    if not name.startswith("_Z"):
        return name
    try:
        out = subprocess.run(["c++filt", name], capture_output=True,
                             text=True, timeout=20)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return name


def load(path):
    with open(path, "rb") as fh:
        d = fh.read()
    magic, = struct.unpack_from("<I", d, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit("%s: not a 64-bit little-endian Mach-O" % path)
    ncmds, = struct.unpack_from("<I", d, 16)
    off = 32
    kexts = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff, size = struct.unpack_from("<QQQ", d, off + 8)
            eid = d[off + 32:off + cmdsize].split(b"\0")[0].decode(
                "utf-8", "replace")
            kexts.append(Kext(d, eid, vmaddr, fileoff, size))
        off += cmdsize
    return d, kexts


def disassemble(data, kext, addr, count):
    """objdump `count` bytes at `addr` (file offset via the kext's segments)."""
    for name, vm, vs, fo, fs in kext.segments:
        if vm <= addr < vm + max(vs, fs):
            off = fo + (addr - vm)
            break
    else:
        print("kcsym: address not backed by a file offset", file=sys.stderr)
        return
    with tempfile.NamedTemporaryFile(prefix="kcsym", suffix=".bin",
                                     delete=False) as tmp:
        tmp.write(data[off:off + count])
        path = tmp.name
    try:
        subprocess.run([OBJDUMP, "-b", "binary", "-m", "aarch64", "-D",
                        "--adjust-vma=%#x" % addr, path])
    finally:
        os.unlink(path)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[2],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("addresses", nargs="*", type=lambda s: int(s, 16),
                    help="collection addresses to name")
    ap.add_argument("--kc", default=DEFAULT_KC, help="kernel collection")
    ap.add_argument("--raw", action="store_true",
                    help="do not demangle symbol names")
    ap.add_argument("--disasm", type=lambda s: int(s, 0), metavar="BYTES",
                    help="disassemble this many bytes at each address")
    ap.add_argument("--kext", help="restrict to this kext (bundle id)")
    ap.add_argument("--symbols", metavar="SUBSTR", default=None,
                    help="list symbols of --kext matching SUBSTR")
    args = ap.parse_args(argv)

    data, kexts = load(args.kc)
    if args.kext:
        kexts = [k for k in kexts if k.entry_id == args.kext]
        if not kexts:
            raise SystemExit("kcsym: no such kext: %s" % args.kext)

    if args.symbols is not None:
        for k in kexts:
            for addr, name in k.symbols():
                if args.symbols in name:
                    print("%#018x  %s" % (addr, name if args.raw
                                          else demangle(name)))
        return 0

    rc = 0
    for addr in args.addresses:
        hit = None
        for k in kexts:
            r = k.resolve(addr)
            if r:
                hit = (k, r)
                break
        if not hit:
            print("%#018x  <unresolved>" % addr)
            rc = 1
            continue
        k, (seg, name, delta) = hit
        pfx = "  " if args.disasm else ""
        if name is None:
            print("%#018x  %s :: %s <no symbol>" % (addr, k.entry_id, seg))
        else:
            shown = name if args.raw else demangle(name)
            print("%#018x  %s :: %s +0x%x  [%s]" % (addr, k.entry_id, shown,
                                                    delta, seg))
        sys.stdout.flush()
        if args.disasm:
            disassemble(data, k, addr, args.disasm)
    return rc


if __name__ == "__main__":
    sys.exit(main())
