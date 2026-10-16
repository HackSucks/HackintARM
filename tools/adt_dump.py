#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""Dump an Apple ADT (Apple Device Tree) blob as an indented tree.

Encoding (see XNU pexpert/... and the VMApple ADT):
    node   = u32 nProperties, u32 nChildren, then nProperties properties,
             then nChildren child nodes (recursively).
    prop   = char name[32], u32 length, value padded to 4 bytes.
             length bit 31 set => value is a C string, low 31 bits = strlen.
"""
import struct
import sys

STRING_BIT = 0x80000000


def rd_prop(d, o):
    name = d[o:o + 32].split(b"\0")[0].decode("latin1")
    (length,) = struct.unpack_from("<I", d, o + 32)
    vstart = o + 36
    n = length & ~STRING_BIT
    raw = d[vstart:vstart + n]
    ascii_ok = n > 0 and all(32 <= c < 127 or c == 0 for c in raw) and any(
        32 <= c < 127 for c in raw)
    if length & STRING_BIT:
        val = '"%s"' % raw.decode("latin1")
    elif n == 4:
        val = "<%#x>" % struct.unpack("<I", raw)[0]
    elif n == 8:
        val = "<%#x>" % struct.unpack("<Q", raw)[0]
    else:
        val = raw.hex()
    if ascii_ok and not (length & STRING_BIT):
        val = "%s  ; %r" % (val, raw.decode("latin1"))
    end = vstart + ((n + 3) & ~3)
    return name, val, end - o


def walk(d, o, depth, out, path):
    nprop, nchild = struct.unpack_from("<II", d, o)
    o += 8
    props = []
    for _ in range(nprop):
        name, val, size = rd_prop(d, o)
        props.append((name, val))
        o += size
    out.append((depth, path, props))
    for _ in range(nchild):
        # child name is encoded as a "name" property of the child
        nprop_c, nchild_c = struct.unpack_from("<II", d, o)
        name = None
        p = o + 8
        for _ in range(nprop_c):
            n, v, size = rd_prop(d, p)
            if n == "name":
                name = v
            p += size
        child_path = path + "/" + (name or "?")
        o = walk(d, o, depth + 1, out, child_path)
    return o


def main():
    path = sys.argv[1]
    d = open(path, "rb").read()
    out = []
    end = walk(d, 0, 0, out, "")
    print("%s: %d bytes, consumed %d" % (path, len(d), end))
    for depth, p, props in out:
        print("  " * depth + (p if p else "/"))
        for name, val in props:
            print("  " * depth + "    %s = %s" % (name, val))


if __name__ == "__main__":
    main()
