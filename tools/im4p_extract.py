#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
im4p_extract.py -- unwrap Apple `.im4p` / IMG4 payloads.

Apple ships almost every boot artifact DER-wrapped:

    SEQUENCE {
        IA5String "IM4P"
        IA5String <type>          e.g. "krnl", "dtre", "ibot", "rkrn"
        IA5String <description>   e.g. "KernelManagement_host-514.0.2"
        OCTET STRING <payload>    may itself begin with "bvx2" (LZFSE)
        ...
    }

The kernelcollection, the device tree and iBoot are all stored this way inside
a restore image.  This tool reports the metadata and writes the payload out;
if the payload is LZFSE-compressed it decompresses it with the `lzfse` binary
(build it from https://github.com/lzfse/lzfse -- BSD-3-Clause).

Usage:
    im4p_extract.py FILE [--payload OUT] [--decompress OUT]
"""

import argparse
import os
import subprocess
import sys


def read_tlv(buf, off):
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise SystemExit("multi-byte tags not supported (tag=%#x)" % tag)
    off += 1
    n = buf[off]
    off += 1
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4:
            raise SystemExit("bad DER length")
        n = int.from_bytes(buf[off:off + k], "big")
        off += k
    return tag, buf[off:off + n], off + n


def parse(buf):
    tag, body, _ = read_tlv(buf, 0)
    if tag != 0x30:
        raise SystemExit("not a DER SEQUENCE (tag=%#x)" % tag)
    out = []
    off = 0
    while off < len(body):
        tag, val, off = read_tlv(body, off)
        out.append((tag, val))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--payload")
    ap.add_argument("--decompress")
    args = ap.parse_args()

    buf = open(args.file, "rb").read()
    fields = parse(buf)
    strings = [v.decode("latin1") for t, v in fields if t == 0x16]
    payloads = [v for t, v in fields if t == 0x04]

    print("file        : %s (%d bytes)" % (args.file, len(buf)))
    print("strings     : %s" % ", ".join(strings))
    print("payloads    : %s" % ", ".join("%d bytes" % len(p) for p in payloads))
    if not payloads:
        raise SystemExit("no OCTET STRING payload found")

    payload = payloads[0]
    lzfse = payload[:4] == b"bvx2"
    print("payload kind: %s" % ("LZFSE (bvx2)" if lzfse else "raw"))

    if args.payload:
        with open(args.payload, "wb") as f:
            f.write(payload)
        print("wrote       : %s" % args.payload)

    if args.decompress:
        payload_path = args.payload or (args.file + ".payload")
        if not args.payload:
            with open(payload_path, "wb") as f:
                f.write(payload)
        if lzfse:
            subprocess.run(["lzfse", "-decode", "-i", payload_path,
                            "-o", args.decompress], check=True)
        else:
            os.replace(payload_path, args.decompress)
        print("wrote       : %s (%d bytes)" % (args.decompress, os.path.getsize(args.decompress)))


if __name__ == "__main__":
    main()
