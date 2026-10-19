#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors
"""Enumerate the Apple VM platform hypercall sites in a kernel collection.

The vmapple kernel calls up to EL2 with `hvc #0` to ask its host for things
only a virtualisation host can give it, and it treats "no answer" as fatal by
branching to itself:

    hvc  #0
    cbnz x0, .          ; spin forever unless the host accepted

The ids live in Apple's 0xc100____ space, i.e. x0 is built from a movz/movk
carrying the 0xc100 halfword in the four instructions before the trap:

    0xc1000000  PAC_INIT_KEY_STATE     (once, at the top of common_start)
    0xc1000001  default ROP/JOP pids   (inlined wherever they are read)
    0xc1000003  publish a vcpu's state to the host
    0xc1000004  companion of the above
    0xc1000005  guest feature query

On a machine whose EL2 is PSCI every one of them comes back NOT_SUPPORTED, so
Gatehouse neutralises exactly the branch to self (gatehouse/src/patch.c,
patch_apple_hypercalls).  This script shows the sites, so the rule and the
count it reports can be checked against the image.

PSCI's CPU_OFF / CPU_DEFAULT_SUSPEND (0x84000002 / 0xc400000e) also end in a
parking loop, but there the CPU is meant never to come back -- those must not
be touched, which is why the rule keys on the 0xc100 halfword and not on the
self-branch alone.  Pass --all to see them too.

Usage: hvc_scan.py [kernel-collection] [--all]
"""
import struct
import sys

LINK_BASE = 0xfffffe0007004000      # collection __TEXT vmaddr (flat 1:1 image)


def rd32(d, off):
    return struct.unpack_from('<I', d, off)[0]


def mov_imm(insn):
    """(reg, imm16, shift) for movz/movk (32- or 64-bit), else None."""
    if (insn & 0xff800000) not in (0x52800000, 0x72800000,
                                   0xd2800000, 0xf2800000):
        return None
    return (insn & 0x1f, (insn >> 5) & 0xffff, ((insn >> 21) & 3) * 16)


def avp_call(d, off):
    """Is x0 built from a 0xc100 halfword just before this hvc?"""
    for k in range(1, 5):
        m = mov_imm(rd32(d, off - 4 * k))
        if m and m[1] == 0xc100:
            return True
    return False


def self_branch(insn):
    """A branch to itself: 'b .' or 'cbz/cbnz wN|xN, .'."""
    if (insn & 0xfc000000) == 0x14000000:
        return (insn & 0x3ffffff) == 0
    if (insn & 0x7f000000) in (0x34000000, 0x35000000):
        return ((insn >> 5) & 0x7ffff) == 0
    return False


def describe(insn):
    m = mov_imm(insn)
    if m:
        kind = "movk" if (insn & 0x00800000) else "movz"
        return "%s %s%d, #0x%x, lsl #%d" % (kind, "x" if insn & 0x80000000 else "w",
                                            m[0], m[1], m[2])
    if (insn & 0xffffffe0) == 0xaa0003e0:
        return "mov x0, x%d" % ((insn >> 16) & 0x1f)
    return "0x%08x" % insn


def main():
    args = [a for a in sys.argv[1:] if a != '--all']
    show_all = '--all' in sys.argv[1:]
    path = args[0] if args else 'kernel/kernelcache.release.vma2.kc'
    with open(path, 'rb') as f:
        d = f.read()

    sites = []
    for off in range(0, len(d) - 8, 4):
        if rd32(d, off) != 0xd4000002:          # hvc #0
            continue
        avp = avp_call(d, off)
        if not avp and not show_all:
            continue
        sites.append((off, avp, self_branch(rd32(d, off + 4))))

    fatal = [s for s in sites if s[2]]
    print("%d %s hvc sites, %d of them spin on themselves"
          % (len(sites), "Apple" if not show_all else "all", len(fatal)))
    for off, avp, spin in sites:
        print("file 0x%-9x VA 0x%-13x %-22s hvc #0; %s%s"
              % (off, LINK_BASE + off, "Apple AVP" if avp else "other",
                 describe(rd32(d, off - 4)),
                 "SPIN ON SELF" if spin else "(returns checked elsewhere)"))


if __name__ == '__main__':
    main()
