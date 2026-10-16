#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
tools/macho_info.py - summarize a Mach-O (arm64e kernel) the way Gatehouse
sees it: link base, entry point, segments, and the flat load plan.
"""
import sys
import struct

LC_SEGMENT_64 = 0x19
LC_UNIXTHREAD = 0x05
LC_MAIN = 0x80000028


def main(path):
    d = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, scmds, flags, res = \
        struct.unpack_from("<IiiIIIII", d, 0)
    print("file            :", path)
    print("magic           : 0x%08x %s" % (magic, "MH_MAGIC_64" if magic == 0xfeedfacf else "?"))
    print("cputype/subtype : 0x%x / 0x%x" % (cputype, cpusub))
    print("filetype/flags  : 0x%x / 0x%x" % (ftype, flags))
    print("ncmds           :", ncmds)
    p = 32
    segs = []
    entry = None
    threads = []
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", d, p)
        if cmd == LC_SEGMENT_64:
            name = d[p + 8:p + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, p + 24)
            maxp, initp, nsects, sflags = struct.unpack_from("<IIII", d, p + 56)
            segs.append((name, vmaddr, vmsize, fileoff, filesize, initp, nsects))
        elif cmd == LC_UNIXTHREAD:
            st = p + 16
            # arm_thread_state64: x[29],fp,lr,sp,pc,cpsr
            pc = struct.unpack_from("<Q", d, st + 256)[0]
            threads.append(pc)
        elif cmd == LC_MAIN:
            entryoff = struct.unpack_from("<Q", d, p + 8)[0]
            entry = ("main", entryoff)
        p += cs
    print()
    print("segments (%d):" % len(segs))
    print("  %-18s %-18s %-10s %-10s %-8s %s" % ("name", "vmaddr", "vmsize", "fileoff", "filesize", "prot"))
    text_base = None
    top = 0
    for name, vmaddr, vmsize, fileoff, filesize, initp, nsects in segs:
        print("  %-18s 0x%016x 0x%08x 0x%08x 0x%08x %s (%d sect)" %
              (name, vmaddr, vmsize, fileoff, filesize,
               "r-x" if initp & 4 else ("rw-" if initp & 2 else "r--"), nsects))
        if name == "__TEXT" and text_base is None:
            text_base = vmaddr
        if name != "__PAGEZERO" and vmaddr + vmsize > top:
            top = vmaddr + vmsize
    print()
    print("VM_KERNEL link base (__TEXT) : 0x%x" % (text_base or 0))
    print("image top                    : 0x%x" % top)
    print("flat span                    : 0x%x (%.1f MiB)" % (top - text_base, (top - text_base) / 1048576))
    print("LC_MAIN entry                :", entry)
    print("LC_UNIXTHREAD pc             : %s" % ", ".join("0x%x" % t for t in threads))
    if threads:
        print("entry offset from __TEXT     : 0x%x" % (threads[0] - text_base))


if __name__ == "__main__":
    main(sys.argv[1])
