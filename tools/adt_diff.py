#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors
#
# tools/adt_diff.py - compare two Apple device trees node by node.
#
# Two things build the platform's tree: gatehouse/dt/build_adt.py for the
# bring-up (Gatehouse hands XNU that one until Trestle owns the boot) and
# Trestle itself (trestle/src/platform_nodes.c and the device models).  They
# have to agree, or the port would boot differently depending on which one
# produced the tree; this is the checker that keeps them honest.
#
# The input is the pexpert encoding both produce:
#
#     DeviceTreeNode         { u32 nProperties; u32 nChildren; }
#     DeviceTreeNodeProperty { char name[32]; u32 length; u8 value[length]; }
#     node := nProperties, nChildren, properties..., children...
#
# Node and property order are deliberately ignored: they are the builders'
# business, not the contract's.  A path present in only one tree, a property
# present in only one, or a property whose value differs is a failure.
#
#     tools/adt_diff.py build/gatehouse.adt /tmp/trestle.adt
#     tools/adt_diff.py --show-same ...
import argparse
import struct
import sys

U32 = struct.Struct("<I")


def parse(blob):
    """Return (path -> {prop: value}), with the root at "/"."""
    flat = {}
    pos = 0

    def walk(path):
        nonlocal pos
        n_props, n_children = struct.unpack_from("<II", blob, pos)
        pos += 8
        props = {}
        name_of_node = None
        for _ in range(n_props):
            raw = blob[pos:pos + 32]
            pos += 32
            name = raw.split(b"\0", 1)[0].decode("ascii", "replace")
            (length,) = U32.unpack_from(blob, pos)
            pos += 4
            value = blob[pos:pos + length]
            pos += (length + 3) & ~3
            if name == "name":
                name_of_node = value.split(b"\0", 1)[0].decode("ascii", "replace")
                continue
            props[name] = value
        flat[path] = props
        for _ in range(n_children):
            child_path = path.rstrip("/") + "/" + peek_name()
            walk(child_path)

    def peek_name():
        # The child's own first property is its "name" (both builders emit it
        # first); fall back to a placeholder if a builder ever stops doing so.
        save = pos
        n_props, _ = struct.unpack_from("<II", blob, save)
        child = save + 8
        for _ in range(n_props):
            raw = blob[child:child + 32]
            child += 32
            name = raw.split(b"\0", 1)[0].decode("ascii", "replace")
            (length,) = U32.unpack_from(blob, child)
            child += 4
            if name == "name":
                value = blob[child:child + length]
                return value.split(b"\0", 1)[0].decode("ascii", "replace")
            child += (length + 3) & ~3
        return "?"

    walk("/")
    return flat


def show(value):
    if len(value) == 0:
        return "<empty>"
    if len(value) >= 2 and value[-1] == 0 and all(32 <= b < 127 for b in value[:-1]):
        return '"%s"' % value[:-1].decode("ascii")
    if len(value) in (4, 8) and len(value) % 4 == 0:
        cells = struct.unpack("<%dI" % (len(value) // 4), value)
        return "<" + " ".join("%#x" % c for c in cells) + ">"
    text = value.hex()
    if len(text) > 64:
        text = text[:64] + "..."
    return "0x" + text


def diff(a, b, show_same, out):
    failures = 0
    for path in sorted(set(a) | set(b)):
        if path not in a:
            print("only in B: node %s" % path, file=out)
            failures += 1
            continue
        if path not in b:
            print("only in A: node %s" % path, file=out)
            failures += 1
            continue
        pa, pb = a[path], b[path]
        if show_same:
            print("node %s" % path, file=out)
        for name in sorted(set(pa) | set(pb)):
            va, vb = pa.get(name), pb.get(name)
            if va is None:
                print("  only in B: %s/%s = %s" % (path, name, show(vb)),
                      file=out)
                failures += 1
            elif vb is None:
                print("  only in A: %s/%s = %s" % (path, name, show(va)),
                      file=out)
                failures += 1
            elif va != vb:
                print("  differs:   %s/%s: A=%s B=%s"
                      % (path, name, show(va), show(vb)), file=out)
                failures += 1
            elif show_same:
                print("  same:      %s/%s = %s" % (path, name, show(va)),
                      file=out)
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a", help="first tree (A), e.g. build/gatehouse.adt")
    ap.add_argument("b", help="second tree (B), e.g. Trestle's output")
    ap.add_argument("--show-same", action="store_true",
                    help="print matching properties too")
    args = ap.parse_args()

    with open(args.a, "rb") as f:
        a = parse(f.read())
    with open(args.b, "rb") as f:
        b = parse(f.read())

    failures = diff(a, b, args.show_same, sys.stdout)
    if failures:
        print("%s: %d difference(s) between %s and %s"
              % (sys.argv[0], failures, args.a, args.b), file=sys.stderr)
        return 1
    print("%s: %s and %s agree (%d nodes)"
          % (sys.argv[0], args.a, args.b, len(a)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
