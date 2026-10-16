#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
tools/pbzx.py - Apple pbzx ("Payload") decompressor.

A pbzx payload is a sequence of independent .xz streams, each preceded by a
small clear-text header.  Different tooling emits slightly different header
layouts, and the header's declared length is not always byte-exact, so we do
not trust it: we locate each stream by its real .xz framing.

  bytes 0..3   b'pbzx'
  u64 BE        flags (nominal uncompressed chunk size, usually 0x01000000)
  then for each chunk:  a 16-byte header, followed by one .xz stream.
  A terminating chunk has a zero header.

.xz streams are self-delimiting: they end with the two-byte footer magic
b'YZ'.  We therefore scan for a footer that is immediately followed by a
plausible next header + .xz magic, and cut there.  Every chunk is then
decoded as an independent .xz stream.

Usage:  pbzx.py PAYLOAD > out.cpio
"""
import sys
import struct
import lzma

XZ_MAGIC = b"\xfd7zX"
XZ_FOOTER = b"YZ"


def iter_streams(data: bytes):
    """Yield each embedded .xz stream (bytes) in order."""
    if data[:4] != b"pbzx":
        raise ValueError("not a pbzx payload")
    n = len(data)
    pos = 28  # 4 magic + 8 flags + first 16-byte chunk header
    while pos < n:
        # Find the next xz footer that is followed by another chunk header.
        cut = -1
        i = data.find(XZ_FOOTER, pos)
        while i != -1:
            end = i + 2
            if end + 20 <= n:
                usize, csize = struct.unpack_from(">QQ", data, end)
                if csize and (usize or csize) and data[end + 16:end + 20] == XZ_MAGIC:
                    cut = end
                    break
            i = data.find(XZ_FOOTER, i + 1)
        if cut == -1:
            # last (or only) stream: take the rest
            yield data[pos:]
            return
        yield data[pos:cut]
        pos = cut + 16


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else None
    f = open(src, "rb", buffering=0) if src else sys.stdin.buffer
    data = f.read()
    out = sys.stdout.buffer
    chunks = 0
    total = 0
    for stream in iter_streams(data):
        # tolerate up to a little trailing padding; xz ignores garbage after
        # the final stream footer only if we strip it ourselves.
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        try:
            blob = dec.decompress(stream)
        except lzma.LZMAError:
            # trim trailing zeros then retry
            trimmed = stream.rstrip(b"\x00")
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            blob = dec.decompress(trimmed)
        # a stream may itself contain concatenated members
        while not dec.eof and dec.needs_input is False:
            blob += dec.decompress(b"")
        out.write(blob)
        chunks += 1
        total += len(blob)
    sys.stderr.write("pbzx: chunks=%d out=%d bytes\n" % (chunks, total))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
