#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
tools/trustcache_add.py - add binaries to an XNU static trust cache.

macOS 27 ships a large part of the system in the SystemOS cryptex.  Those
files are platform binaries: their code signature carries a platform
identifier, and AMFI refuses to map them unless the binary's cdhash is named by
the boot trust cache.  Transplanting a cryptex file into the System volume
therefore has two halves:

    1. install the file itself (tools/mkcombined -inject / -inject-decmpfs), and
    2. add the cdhash of every Mach-O slice to the trust cache Gatehouse gives
       XNU.

This tool does (2).  It reads the platform trust cache from the IPSW (an IMG4
object whose payload is a trust_cache_module1, as XNU's osfmk/kern/trustcache.h
defines it), appends one entry per slice, keeps the table sorted by cdhash as
XNU requires, and writes a *raw* trust cache module.  Gatehouse accepts a raw
module directly: its IMG4 unwrapper falls back to the whole file, and XNU only
ever sees the module.

    tools/trustcache_add.py --in kernel/trustcache.release.vma2 \\
        --out build/trustcache.release.vma2 \\
        /path/to/libLaunchServicesSupport.dylib

The output must be passed to qemu/run.sh as TRUSTCACHE=... .  The input file in
kernel/ is never modified: it is the IPSW's artifact and stays pristine.

Code signing structures (SuperBlob, CodeDirectory) are big-endian, unlike the
Mach-O load commands that point at them.
"""

import argparse
import hashlib
import struct
import sys

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02

LC_CODE_SIGNATURE = 0x1D

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA


def der_next(buf, off):
    """Return (tag, value, next_offset) for the DER element at off."""
    if off + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[off]
    off += 1
    length = buf[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        if off + n > len(buf):
            raise ValueError("truncated DER length")
        length = int.from_bytes(buf[off:off + n], "big")
        off += n
    if off + length > len(buf):
        raise ValueError("DER value overruns buffer")
    return tag, buf[off:off + length], off + length


def im4p_payload(data):
    """Return the payload OCTET STRING of an IMG4/IM4P object, or data itself.

    This mirrors gatehouse/src/main.c:img4_payload(): the container is
    SEQUENCE { "IM4P", <type>, <version>, OCTET STRING payload }.  Anything
    that is not such a container is treated as an already-raw payload.
    """
    if len(data) < 4 or data[0] != 0x30:
        return data
    try:
        tag, seq, _ = der_next(data, 0)
        if tag != 0x30:
            return data
        p = 0
        parts = []
        while p < len(seq):
            t, v, p = der_next(seq, p)
            parts.append((t, v))
        if len(parts) < 4 or parts[0][0] != 0x16 or parts[0][1] != b"IM4P":
            return data
        if parts[3][0] != 0x04:
            raise ValueError("IMG4 payload is not an OCTET STRING")
        return parts[3][1]
    except ValueError:
        return data


def parse_module(payload):
    """Split a version 1 or 2 trust cache module into header and entries."""
    if len(payload) < 24:
        raise ValueError("trust cache module too short")
    version, uuid, count = struct.unpack_from("<I16sI", payload, 0)
    if version == 1:
        entry_size = 22
    elif version == 2:
        entry_size = 24
    else:
        raise ValueError("unsupported trust cache version %d" % version)
    if 24 + count * entry_size != len(payload):
        raise ValueError("trust cache length does not match %d entries" % count)
    entries = [payload[24 + i * entry_size:24 + (i + 1) * entry_size]
               for i in range(count)]
    return version, uuid, entries


def _slices(data):
    """Yield each thin Mach-O image in a thin or fat file."""
    if len(data) < 8:
        raise ValueError("too short to be Mach-O")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic == FAT_MAGIC:
        count = struct.unpack_from(">I", data, 4)[0]
        for i in range(count):
            _, _, off, size, _ = struct.unpack_from(">iiIII", data, 8 + i * 20)
            yield data[off:off + size]
        return
    if magic == FAT_CIGAM:
        count = struct.unpack_from("<I", data, 4)[0]
        for i in range(count):
            _, _, off, size, _ = struct.unpack_from("<iiIII", data, 8 + i * 20)
            yield data[off:off + size]
        return
    yield data


def _cdhash_one(slice_data):
    if len(slice_data) < 32:
        raise ValueError("short Mach-O slice")
    magic = struct.unpack_from("<I", slice_data, 0)[0]
    if magic != 0xFEEDFACF:
        raise ValueError("not a 64-bit little-endian Mach-O slice: %#x" % magic)
    ncmds = struct.unpack_from("<I", slice_data, 16)[0]
    p = 32
    sig = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", slice_data, p)
        if size < 8:
            raise ValueError("bad load command size")
        if cmd == LC_CODE_SIGNATURE:
            sig = struct.unpack_from("<II", slice_data, p + 8)
            break
        p += size
    if sig is None:
        raise ValueError("no LC_CODE_SIGNATURE")
    dataoff, datasize = sig
    blob = slice_data[dataoff:dataoff + datasize]
    if len(blob) != datasize:
        raise ValueError("code signature overruns slice")
    smagic, _, count = struct.unpack_from(">III", blob, 0)
    if smagic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise ValueError("not an embedded-signature SuperBlob")
    cdir = None
    for i in range(count):
        btype, boff = struct.unpack_from(">II", blob, 12 + i * 8)
        if btype == 0:                      # CSSLOT_CODEDIRECTORY
            cmagic, clen = struct.unpack_from(">II", blob, boff)
            if cmagic != CSMAGIC_CODEDIRECTORY:
                raise ValueError("bad CodeDirectory magic")
            cdir = blob[boff:boff + clen]
            break
    if cdir is None:
        raise ValueError("no CodeDirectory")
    hash_type = cdir[37]
    if hash_type == 2:                      # CS_HASHTYPE_SHA256
        digest = hashlib.sha256(cdir).digest()
    elif hash_type == 4:                    # CS_HASHTYPE_SHA384
        digest = hashlib.sha384(cdir).digest()
    else:
        raise ValueError("unsupported CodeDirectory hash type %d" % hash_type)
    return digest[:20], hash_type


def cdhashes(path):
    data = open(path, "rb").read()
    out = []
    for sl in _slices(data):
        out.append(_cdhash_one(sl))
    return out


def main():
    ap = argparse.ArgumentParser(description="add binaries to an XNU trust cache")
    ap.add_argument("--in", dest="src", required=True,
                    help="platform trust cache (IMG4 or raw module)")
    ap.add_argument("--out", dest="dst", required=True,
                    help="output raw trust cache module")
    ap.add_argument("files", nargs="+", help="Mach-O files to trust")
    args = ap.parse_args()

    payload = im4p_payload(open(args.src, "rb").read())
    version, uuid, entries = parse_module(payload)
    if version == 1:
        # Version 2 only adds the constraint category; promote so the new
        # entries have somewhere to carry it (zero means unconstrained).
        entries = [e + b"\x00\x00" for e in entries]
        version = 2
        entry_size = 24
    else:
        entry_size = 24

    known = {e[:20] for e in entries}
    added = 0
    for path in args.files:
        for digest, hash_type in cdhashes(path):
            if digest in known:
                continue
            # cdhash, hash type, flags (platform entries carry 0), constraint
            # category (none), reserved.
            entries.append(digest + bytes([hash_type, 0, 0, 0]))
            known.add(digest)
            added += 1
            print("added %s %s" % (digest.hex(), path), file=sys.stderr)

    entries.sort(key=lambda e: e[:20])
    out = struct.pack("<I16sI", version, uuid, len(entries))
    out += b"".join(entries)
    with open(args.dst, "wb") as f:
        f.write(out)
    print("wrote %s: version %d, %d entries (%d added)"
          % (args.dst, version, len(entries), added), file=sys.stderr)

    if added == 0:
        print("warning: nothing was added", file=sys.stderr)


if __name__ == "__main__":
    main()