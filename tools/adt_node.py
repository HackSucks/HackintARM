#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""Print the raw properties (name, byte length, hex) of ADT nodes by path.

A companion to adt_dump.py: adt_dump.py prints the whole tree, this prints the
exact bytes of selected nodes so a synthetic tree can be diffed against the
authentic one (kernel/DeviceTree.vma2macosap.adt).

Usage: adt_node.py <adt-file> <path> [<path> ...]
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adt_dump import rd_prop  # noqa: E402


def node_name(d, o):
    nprop = struct.unpack_from("<I", d, o)[0]
    p = o + 8
    for _ in range(nprop):
        n, _v, size = rd_prop(d, p)
        if n == "name":
            ln = struct.unpack_from("<I", d, p + 32)[0] & 0x7FFFFFFF
            return d[p + 36:p + 36 + ln].split(b"\0")[0].decode("latin1")
        p += size
    return "?"


def walk(d, o, path, want, out):
    nprop, nchild = struct.unpack_from("<II", d, o)
    p = o + 8
    props = []
    for _ in range(nprop):
        n, _val, size = rd_prop(d, p)
        ln = struct.unpack_from("<I", d, p + 32)[0] & 0x7FFFFFFF
        raw = d[p + 36:p + 36 + ln]
        props.append((n, raw))
        p += size
    if path in want:
        out.append((path, props))
    for _ in range(nchild):
        p = walk(d, p, path + "/" + node_name(d, p), want, out)
    return p


def main():
    d = open(sys.argv[1], "rb").read()
    want = set(sys.argv[2:])
    out = []
    walk(d, 0, "", want, out)
    for path, props in out:
        print("=== %s (%d props)" % (path, len(props)))
        for n, raw in props:
            print("    %-34s len=%-4d %s" % (n, len(raw), raw.hex()))


if __name__ == "__main__":
    main()
