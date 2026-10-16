#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""Reference implementation of XNU chained-fixups application (loader side).

Gatehouse does this for kernels that are not kernel-collections: the pointer
format is DYLD_CHAINED_PTR_ARM64E_OFFSET (7); every chain entry is either a
plain rebase or an authenticated rebase.  `segment_offset` is a vm offset from
the image base, so the file offset must be derived from the segment table.
"""
import struct, sys

LINK_BASE = 0xfffffe0007004000
PTR_ARM64E = 7

def parse(d):
    (magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, _) = \
        struct.unpack_from('<8I', d, 0)
    segs, chained = [], None
    o = 32
    for _ in range(ncmds):
        cmd, cmdsz = struct.unpack_from('<II', d, o)
        if cmd == 0x19:
            name = struct.unpack_from('<16s', d, o + 8)[0].split(b'\0')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, o + 24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd == 0x80000034:
            _, _, dataoff, datasize = struct.unpack_from('<IIII', d, o)
            chained = (dataoff, datasize)
        o += cmdsz
    return segs, chained, flags

def va2fo(segs, va):
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        if vmaddr <= va < vmaddr + vmsize:
            d_off = va - vmaddr
            return (fileoff + d_off) if d_off < filesize else None
    return None

def apply(d, sign=None):
    segs, chained, flags = parse(d)
    dataoff, datasize = chained
    b = d[dataoff:dataoff + datasize]
    (ver, starts_off, imports_off, symbols_off,
     imports_count, imports_fmt, symbols_fmt) = struct.unpack_from('<7I', b, 0)
    assert imports_count == 0, "bind fixups present"
    seg_count = struct.unpack_from('<I', b, starts_off)[0]
    plain = auth = 0
    per = []
    for i in range(seg_count):
        so = struct.unpack_from('<I', b, starts_off + 4 + i * 4)[0]
        if so == 0:
            continue
        p = starts_off + so
        size, page_size, pfmt = struct.unpack_from('<IHH', b, p)
        seg_off, max_valid = struct.unpack_from('<QI', b, p + 8)
        page_count = struct.unpack_from('<H', b, p + 20)[0]
        starts = struct.unpack_from('<%dH' % page_count, b, p + 22)
        assert pfmt == PTR_ARM64E, pfmt
        np = na = 0
        for pg, ps in enumerate(starts):
            if ps == 0xFFFF:
                continue
            voff = seg_off + pg * page_size + ps
            while True:
                va = LINK_BASE + voff
                fo = va2fo(segs, va)
                if fo is None:
                    raise SystemExit("fixup at unmapped va %#x" % va)
                val = struct.unpack_from('<Q', d, fo)[0]
                a = (val >> 63) & 1
                if (val >> 62) & 1:
                    raise SystemExit("bind fixup at %#x" % va)
                nxt = (val >> 51) & 0x7FF
                if a:
                    target = val & 0xFFFFFFFF
                    diversity = (val >> 32) & 0xFFFF
                    addrdiv = (val >> 48) & 1
                    key = (val >> 49) & 3
                    ptr = LINK_BASE + target
                    if sign:
                        ptr = sign(ptr, diversity, addrdiv, key)
                    na += 1
                else:
                    target = val & ((1 << 43) - 1)
                    high8 = (val >> 43) & 0xFF
                    ptr = LINK_BASE + target + (high8 << 56)
                    np += 1
                struct.pack_into('<Q', d, fo, ptr)
                if nxt == 0:
                    break
                voff += nxt * 4
        per.append((i, segs[i][0] if i < len(segs) else '?', np, na))
        plain += np
        auth += na
    for i, nm, np, na in per:
        print("  seg[%d] %-16s plain=%-6d auth=%d" % (i, nm, np, na))
    print("total plain=%d auth=%d" % (plain, auth))
    return plain, auth

if __name__ == '__main__':
    d = bytearray(open(sys.argv[1], 'rb').read())
    apply(d, sign=None)
    segs, _, _ = parse(bytes(d))
    va = 0xfffffe00081cb0e8
    fo = va2fo(segs, va)
    w = struct.unpack_from('<Q', d, fo)[0]
    print("word at %#x (file %#x) = %#018x" % (va, fo, w))
    fo2 = va2fo(segs, w)
    print("  deref %#x -> file %s bytes %s" %
          (w, hex(fo2) if fo2 else None, d[fo2:fo2 + 24].hex(' ') if fo2 else '-'))
