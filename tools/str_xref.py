#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors
"""Locate a function in a kernel collection by a C string it references.

Apple's compiler materialises a string address as an adjacent pair

    adrp xN, <page>
    add  xN, xN, #<offset>

so a string reference is an unambiguous pointer to the function that uses it.
Walking back from the reference to the nearest "pacibsp" (the arm64e prologue
every function in the collection shares) finds that function's entry point,
and scanning "bl" encodings finds its callers.

This is the locator gatehouse/src/patch.c implements in C to find the functions
it edits; keeping a Python equivalent makes the byte-verified claims in the
prompt/boot log reproducible against a new image.

Usage: str_xref.py <kernel-collection> <string> [<string> ...]
"""
import struct
import sys

LINK_BASE = 0xfffffe0007004000      # collection __TEXT vmaddr (flat 1:1 image)
BTI_C = 0xd503245f
PACIBSP = 0xd503237f


def rd32(d, off):
    return struct.unpack_from('<I', d, off)[0]


def adrp_page(insn, pc):
    if (insn & 0x9f000000) != 0x90000000:
        return None
    imm = (((insn >> 5) & 0x7ffff) << 2) | ((insn >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xfff) + (imm << 12)


def add_imm(insn):
    """ADD (immediate), 64-bit, no shift, rd == rn -> imm12."""
    if (insn & 0x7f000000) != 0x11000000 or (insn & 0x80000000) == 0:
        return None
    if ((insn >> 22) & 3) != 0 or (insn & 0x1f) != ((insn >> 5) & 0x1f):
        return None
    return (insn >> 10) & 0xfff


def bl_target(insn, pc):
    if (insn & 0xfc000000) != 0x94000000:
        return None
    imm = insn & 0x3ffffff
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + (imm << 2)


def string_refs(d, sva):
    """File offsets of adrp+add pairs that materialise sva."""
    page = sva & ~0xfff
    for off in range(0, len(d) - 8, 4):
        if adrp_page(rd32(d, off), LINK_BASE + off) != page:
            continue
        imm = add_imm(rd32(d, off + 4))
        if imm is not None and page + imm == sva:
            yield off


def function_entry(d, ref):
    """Nearest preceding pacibsp (plus its bti c, when present)."""
    e = ref
    while e >= 4 and rd32(d, e) != PACIBSP:
        e -= 4
    if e < 4:
        return None
    if rd32(d, e - 4) == BTI_C:
        e -= 4
    return e


def callers(d, entry_va):
    return [off for off in range(0, len(d) - 4, 4)
            if bl_target(rd32(d, off), LINK_BASE + off) == entry_va]


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    d = open(sys.argv[1], 'rb').read()
    for s in sys.argv[2:]:
        needle = s.encode() + b'\0'
        off = d.find(needle)
        if off < 0:
            print("%s: not present" % s)
            continue
        while off >= 0:
            sva = LINK_BASE + off
            refs = list(string_refs(d, sva))
            if not refs:
                print("%s: string at file 0x%x (VA 0x%x), no adrp+add reference"
                      % (s, off, sva))
            for ref in refs:
                entry = function_entry(d, ref)
                if entry is None:
                    print("%s: reference at file 0x%x, no prologue found"
                          % (s, ref))
                    continue
                calls = callers(d, LINK_BASE + entry)
                print("%-40s entry VA 0x%x (file 0x%x), %d bl caller(s): %s"
                      % (s, LINK_BASE + entry, entry, len(calls),
                         ", ".join("0x%x" % c for c in calls)))
                print("%-40s first reference at VA 0x%x"
                      % ("", LINK_BASE + ref))
            off = d.find(needle, off + 1)


if __name__ == '__main__':
    main()
