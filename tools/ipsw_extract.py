#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
ipsw_extract.py -- pull individual members out of a (huge) Apple IPSW over HTTP.

Apple's restore images are ~25 GiB ZIP archives and we usually want a handful of
files out of them: the kernelcache (the kernel collection: XNU + every prelinked
kext), BuildManifest.plist, and the root-volume images.  Downloading the whole
archive to read one member is wasteful, so instead we

  1. read the zip64 end-of-central-directory record with a small Range request,
  2. Range-fetch the central directory and parse the member list,
  3. Range-fetch the wanted member (local header + data) and stream it out.

Members can be several GiB (the root-volume DMGs), so extraction streams to the
output file in chunks instead of buffering the whole member.  A stored member
(method 0) is byte-identical to its data in the archive, so a partial output
file is resumed on a re-run -- a dropped connection over a 25 GiB archive is
recoverable by just running the same command again.

This needs the server to honour Range requests; Apple's CDN does.

Usage:
    ipsw_extract.py --url URL --list [--match SUBSTR]
    ipsw_extract.py --url URL --extract NAME --out PATH
"""

import argparse
import os
import struct
import time
import urllib.request
import zlib

BLOCK = 1 << 17          # window used to find the end-of-central-directory
CHUNK = 32 << 20         # Range-fetch granularity while extracting
RETRIES = 8


def content_length(url):
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers["Content-Length"])


def fetch(url, start, end):
    """Range-fetch [start, end] inclusive, with backoff on transient errors."""
    last = None
    for attempt in range(RETRIES):
        try:
            req = urllib.request.Request(
                url, headers={"Range": "bytes=%d-%d" % (start, end)})
            with urllib.request.urlopen(req, timeout=180) as r:
                return r.read()
        except Exception as e:                      # noqa: BLE001
            last = e
            time.sleep(min(2 ** attempt, 30))
    raise last


def zip64_directory(url, size):
    """Return (cd_offset, cd_size, entry_count)."""
    tail = fetch(url, max(0, size - BLOCK), size - 1)

    # zip64 end of central directory locator
    i = tail.rfind(b"PK\x06\x07")
    if i < 0:
        raise SystemExit("no zip64 EOCD locator (not a zip64 archive?)")
    rec_off = struct.unpack_from("<Q", tail, i + 8)[0]

    rec = fetch(url, rec_off, rec_off + 55)
    if rec[:4] != b"PK\x06\x06":
        raise SystemExit("bad zip64 EOCD record signature")
    count, cd_size, cd_off = struct.unpack_from("<QQQ", rec, 32)
    return cd_off, cd_size, count


def parse_central_directory(cd):
    """Yield dicts describing each member."""
    off = 0
    while off + 46 <= len(cd) and cd[off:off + 4] == b"PK\x01\x02":
        # sig(4) madeby(2) need(2) flags(2) method(2) time(2) date(2)
        # crc(4) csize(4) usize(4) nlen(2) elen(2) clen(2) disk(2) iattr(2)
        # eattr(4) lho(4), then name
        method = struct.unpack_from("<H", cd, off + 10)[0]
        csize, usize = struct.unpack_from("<II", cd, off + 20)
        nlen, elen, clen = struct.unpack_from("<HHH", cd, off + 28)
        lho = struct.unpack_from("<I", cd, off + 42)[0]
        name = cd[off + 46:off + 46 + nlen].decode("utf-8", "replace")
        extra = cd[off + 46 + nlen:off + 46 + nlen + elen]

        # zip64 extra: fields are present only where the 32-bit slot was 0xffffffff
        if 0xFFFFFFFF in (csize, usize, lho):
            e = 0
            while e + 4 <= len(extra):
                eid, esz = struct.unpack_from("<HH", extra, e)
                if eid == 0x0001:
                    p = e + 4
                    if usize == 0xFFFFFFFF:
                        usize = struct.unpack_from("<Q", extra, p)[0]; p += 8
                    if csize == 0xFFFFFFFF:
                        csize = struct.unpack_from("<Q", extra, p)[0]; p += 8
                    if lho == 0xFFFFFFFF:
                        lho = struct.unpack_from("<Q", extra, p)[0]; p += 8
                e += 4 + esz

        yield dict(name=name, method=method, csize=csize, usize=usize, lho=lho)
        off += 46 + nlen + elen + clen


def data_offset(url, member):
    """Read the member's local header to locate its data (CD extra may differ)."""
    hdr = fetch(url, member["lho"], member["lho"] + 29)
    if hdr[:4] != b"PK\x03\x04":
        raise SystemExit("bad local header for %s" % member["name"])
    nlen, elen = struct.unpack_from("<HH", hdr, 26)
    return member["lho"] + 30 + nlen + elen


def extract(url, member, out_path, resume=True):
    doff = data_offset(url, member)
    csize, usize = member["csize"], member["usize"]
    print("extracting %s (compressed %d, uncompressed %d, method %d)"
          % (member["name"], csize, usize, member["method"]), flush=True)
    t0 = time.time()

    if member["method"] == 0:
        # stored: the archive bytes are the file, so resume a partial output.
        have = os.path.getsize(out_path) if (resume and os.path.exists(out_path)) else 0
        if have > csize:
            have = 0
        if have:
            print("  resuming at %d/%d (%.1f%%)" % (have, csize, 100.0 * have / csize),
                  flush=True)
        with open(out_path, "r+b" if have else "wb") as f:
            f.seek(have)
            pos = have
            while pos < csize:
                n = min(CHUNK, csize - pos)
                f.write(fetch(url, doff + pos, doff + pos + n - 1))
                pos += n
                mb = (pos - have) / (1 << 20)
                rate = mb / max(time.time() - t0, 1e-6)
                print("  %6.2f%%  %d/%d  (%.1f MiB/s)"
                      % (100.0 * pos / csize, pos, csize, rate),
                      end="\r", flush=True)
        print()
    elif member["method"] == 8:
        # deflate: stream-decompress (cannot resume mid-stream).
        d = zlib.decompressobj(-15)
        pos = 0
        with open(out_path, "wb") as f:
            while pos < csize:
                n = min(CHUNK, csize - pos)
                f.write(d.decompress(fetch(url, doff + pos, doff + pos + n - 1)))
                pos += n
                print("  %6.2f%%" % (100.0 * pos / csize), end="\r", flush=True)
            f.write(d.flush())
        print()
    else:
        raise SystemExit("unsupported compression method %d" % member["method"])

    got = os.path.getsize(out_path)
    if got != usize:
        raise SystemExit("size mismatch: got %d want %d" % (got, usize))
    print("wrote %s (%d bytes)" % (out_path, got), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--match", default=None)
    ap.add_argument("--extract")
    ap.add_argument("--out")
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()

    size = content_length(args.url)
    cd_off, cd_size, count = zip64_directory(args.url, size)
    print("archive size %d, %d members, central directory at %d (%d bytes)"
          % (size, count, cd_off, cd_size))
    cd = fetch(args.url, cd_off, cd_off + cd_size - 1)
    members = list(parse_central_directory(cd))

    if args.extract:
        hits = [m for m in members if m["name"] == args.extract]
        if not hits:
            raise SystemExit("no such member: %s" % args.extract)
        if not args.out:
            raise SystemExit("--out is required with --extract")
        extract(args.url, hits[0], args.out, resume=not args.no_resume)
        return

    for m in members:
        if args.match and args.match not in m["name"]:
            continue
        print("%14d  %14d  m%d  %s"
              % (m["usize"], m["csize"], m["method"], m["name"]))


if __name__ == "__main__":
    main()
