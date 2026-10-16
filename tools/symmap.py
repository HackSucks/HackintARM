#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
tools/symmap.py - name addresses in the stripped RELEASE kernel.

The RELEASE `kernel.release.vmapple` ships a nearly-empty LC_SYMTAB (a few
thousand exported names); a DEVELOPMENT build of the same XNU source
(`kernel.development.vmapple`) ships a full symbol table.  The two are not
address-compatible -- different __TEXT_EXEC vmaddrs and a different LC_UUID --
so names cannot be copied by address.  They *can* be transferred structurally,
because both kernels are the same source compiled by the same toolchain and the
linker emits functions in the same order:

  1. Parse the Mach-O load commands of both files: LC_SEGMENT_64 (0x19) for the
     segment map, LC_SYMTAB (0x02) for names/addresses and LC_FUNCTION_STARTS
     (0x26) for the ordered list of function entry points.  The function-start
     list is a run of ULEB128 deltas relative to the image base (`__TEXT`); the
     first entry lands on the start of `__TEXT_EXEC` in both kernels.  Only
     function starts and symbols inside `__TEXT_EXEC` are considered.
  2. Collect the symbol names present in *both* builds whose address is exactly a
     function start in each.  Those become *anchors*: a release address and the
     development address of the same function.  A name match is trusted even
     where the two builds reordered a function, so every anchor is pinned to its
     own name; the increasing subset of anchors bounds the intervals.
  3. Walk the anchors in address order and split the ordered function-start list
     into intervals.  Between two consecutive anchors codegen may inline (or
     outline) functions, so the two builds can have a different number of
     function starts; when the counts match the interval is emitted in the same
     order in both builds and is mapped 1:1.  When they differ the interval is
     left unresolved and recorded.
  4. For unresolved intervals a content fallback matches functions whose body
     bytes hash identically in both builds (raw bytes, then a relaxed hash that
     masks PC-relative branch/ADR immediates so only the frame-relative code
     needs to agree).  Only unique matches are accepted.
  5. An address is named by the release function start it falls in; if that
     function is unresolved the nearest preceding resolved function is reported
     with a `+0xNN` offset, flagged as a gap.

Because the kernels are usually inspected at their runtime (slid) addresses --
e.g. 0xfffffe0009f4348c in a boot log -- the slide is auto-detected when the
supplied addresses sit outside the release image: the correct slide makes the
most addresses land exactly on release function starts.  `--slide HEX` forces a
value and `--slide 0` treats the addresses as link-time addresses.

Usage:
    symmap.py 0xfffffe0009f4348c 0xfffffe0009f459d8
    symmap.py --stats 0xfffffe0009f4348c
    symmap.py --dump-cache
"""

import argparse
import bisect
import hashlib
import os
import struct
import sys
from collections import Counter

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_FUNCTION_STARTS = 0x26
MH_MAGIC_64 = 0xFEEDFACF

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASE_PATH = os.path.join(REPO, "kernel", "kernel.release.vmapple")
DEVELOPMENT_PATH = os.path.join(REPO, "kernel", "kernel.development.vmapple")
CACHE_PATH = os.path.join(REPO, "build", "symmap_release.txt")


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------

def uleb128(data, off):
    """Decode one ULEB128 value; return (value, new_offset)."""
    val = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, off
        shift += 7


class MachO:
    """Just enough Mach-O to read segments, the symbol table and function starts."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        magic, = struct.unpack_from("<I", self.data, 0)
        if magic != MH_MAGIC_64:
            raise SystemExit("%s: not a 64-bit little-endian Mach-O (magic %#x)"
                             % (path, magic))
        ncmds = struct.unpack_from("<I", self.data, 16)[0]
        self.segments = {}          # name -> (vmaddr, vmsize, fileoff, filesize)
        self.seglist = []           # same tuples, load-command order
        self.symtab = None          # (symoff, nsyms, stroff, strsize)
        self.func_starts = None     # (dataoff, datasize)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmd == LC_SEGMENT_64:
                name = self.data[off + 8:off + 24].split(b"\0")[0].decode()
                seg = struct.unpack_from("<QQQQ", self.data, off + 24)
                self.segments[name] = seg
                self.seglist.append(seg)
            elif cmd == LC_SYMTAB:
                self.symtab = struct.unpack_from("<IIII", self.data, off + 8)
            elif cmd == LC_FUNCTION_STARTS:
                self.func_starts = struct.unpack_from("<II", self.data, off + 8)
            off += cmdsize

    @property
    def link_base(self):
        return self.segments.get("__TEXT", (0,))[0]

    def va_to_file(self, va):
        for vmaddr, vmsize, fileoff, filesize in self.seglist:
            if vmaddr <= va < vmaddr + vmsize and va - vmaddr < filesize:
                return fileoff + (va - vmaddr)
        return None

    def body(self, start, stop):
        """Raw bytes of [start, stop), clamped to what the file actually holds."""
        a = self.va_to_file(start)
        b = self.va_to_file(stop)
        if a is None:
            return b""
        if b is None or b < a:
            b = a + (stop - start)
        return self.data[a:b]


class Kernel:
    """One Mach-O kernel reduced to the __TEXT_EXEC function/symbol view."""

    def __init__(self, path):
        self.macho = MachO(path)
        te = self.macho.segments["__TEXT_EXEC"]
        self.te_lo, self.te_hi = te[0], te[0] + te[1]
        live = [(vm, vs) for vm, vs, _, _ in self.macho.seglist if vs > 0]
        self.image_lo = min(vm for vm, _ in live)
        self.image_hi = max(vm + vs for vm, vs in live)
        self.fs = self._function_starts()
        self.fs_set = set(self.fs)
        self.sym_by_name = self._symbols()
        self.name_by_addr = {}
        for name, addrs in self.sym_by_name.items():
            for addr in addrs:
                cur = self.name_by_addr.get(addr)
                if cur is None or (len(name), name) < (len(cur), cur):
                    self.name_by_addr[addr] = name

    def _function_starts(self):
        if self.macho.func_starts is None:
            return []
        dataoff, datasize = self.macho.func_starts
        out = []
        cur = 0
        off = dataoff
        end = dataoff + datasize
        while off < end:
            delta, off = uleb128(self.macho.data, off)
            if delta == 0:          # terminating zero delta
                break
            cur += delta
            out.append(self.macho.link_base + cur)
        return [a for a in out if self.te_lo <= a < self.te_hi]

    def body_at(self, index):
        """Raw bytes of the function whose start is fs[index]."""
        start = self.fs[index]
        stop = self.fs[index + 1] if index + 1 < len(self.fs) else self.te_hi
        return self.macho.body(start, stop)

    def _symbols(self):
        symoff, nsyms, stroff, strsize = self.macho.symtab
        strtab = self.macho.data[stroff:stroff + strsize]
        out = {}
        for i in range(nsyms):
            n_strx, _n_type, _n_sect, _n_desc, n_value = \
                struct.unpack_from("<IBBHQ", self.macho.data, symoff + i * 16)
            if not (self.te_lo <= n_value < self.te_hi):
                continue
            end = strtab.find(b"\0", n_strx)
            if end < 0:
                continue
            name = strtab[n_strx:end].decode("utf-8", "replace")
            if name:
                out.setdefault(name, []).append(n_value)
        return out


# ---------------------------------------------------------------------------
# Structural transfer
# ---------------------------------------------------------------------------

def build_anchors(release, dev):
    """Name-matched anchors between the two kernels.

    Returns (monotonic, pinned, dropped):
      * pinned    - {release_addr: dev_addr} for every unique, unambiguous
                    symbol name sitting on a function start in both kernels.
      * monotonic - the increasing subset of pinned, used to partition the
                    ordered function-start lists into intervals.
    A handful of functions are reordered between the builds, so `pinned` can be
    locally non-monotonic; those entries are still trusted by name.
    """
    pairs = {}
    for name in set(release.sym_by_name) & set(dev.sym_by_name):
        ra = release.sym_by_name[name]
        da = dev.sym_by_name[name]
        if len(ra) != 1 or len(da) != 1:
            continue
        ra, da = ra[0], da[0]
        if ra not in release.fs_set or da not in dev.fs_set:
            continue
        key = (ra, da)
        cur = pairs.get(key)
        if cur is None or (len(name), name) < (len(cur), cur):
            pairs[key] = name
    ordered = sorted((ra, da, name) for (ra, da), name in pairs.items())
    pinned = {}
    for ra, da, _name in ordered:
        pinned.setdefault(ra, da)
    monotonic = []
    last = -1
    prev_ra = -1
    for ra, da, name in ordered:
        if da < last or ra == prev_ra:   # disagreement: not usable as a bound
            continue
        monotonic.append((ra, da, name))
        last = da
        prev_ra = ra
    return monotonic, pinned, len(ordered) - len(monotonic)


def build_mapping(release, dev, anchors):
    """Anchor-bounded 1:1 transfer of the ordered function-start lists.

    Returns (mapping, intervals, resolved_intervals, skipped_intervals) where
    mapping is {release_func_start: dev_func_start} and each interval is
    (release_index, dev_index, release_count, dev_count, resolved).
    """
    r_idx = [bisect.bisect_left(release.fs, a[0]) for a in anchors]
    d_idx = [bisect.bisect_left(dev.fs, a[1]) for a in anchors]
    mapping = {}
    for i in range(len(anchors)):
        mapping[release.fs[r_idx[i]]] = dev.fs[d_idx[i]]

    intervals = []
    resolved = skipped = 0
    for i in range(len(anchors) - 1):
        rc = r_idx[i + 1] - r_idx[i]
        dc = d_idx[i + 1] - d_idx[i]
        if rc > 0 and rc == dc:
            for k in range(1, rc):
                mapping[release.fs[r_idx[i] + k]] = dev.fs[d_idx[i] + k]
            intervals.append((r_idx[i], d_idx[i], rc, dc, True))
            resolved += 1
        else:
            intervals.append((r_idx[i], d_idx[i], rc, dc, False))
            skipped += 1
    return mapping, intervals, resolved, skipped


def _normalize(body):
    """Mask PC-relative immediates so two builds' bodies can compare equal."""
    out = bytearray()
    n = len(body) - len(body) % 4
    for i in range(0, n, 4):
        w, = struct.unpack_from("<I", body, i)
        if (w & 0x7C000000) in (0x14000000, 0x94000000):        # B / BL
            w &= 0xFC000000
        elif (w & 0xFF000010) == 0x54000000:                    # B.cond
            w &= 0xFF00001F
        elif (w & 0x7E000000) == 0x34000000:                    # CBZ / CBNZ
            w &= 0xFF00001F
        elif (w & 0x7E000000) == 0x36000000:                    # TBZ / TBNZ
            w &= 0xFFF8001F
        elif (w & 0x1F000000) == 0x10000000:                    # ADR / ADRP
            w &= 0x9F00001F
        elif (w & 0x3B000000) == 0x18000000:                    # LDR literal
            w &= 0xFF00001F
        out += struct.pack("<I", w)
    if n < len(body):
        out += body[n:]
    return bytes(out)


def content_fallback(release, dev, mapping, intervals, extra_used=()):
    """Match byte-identical bodies inside skipped intervals (unique only).

    For each release function in turn the raw body hash is tried first, then a
    relaxed hash that masks PC-relative immediates.  A match is accepted only
    when it is unique and keeps the transfer monotonic (strictly increasing dev
    address within the interval).  `extra_used` are dev addresses already
    claimed by the name-matched anchors.
    """
    used = set(mapping.values()) | set(extra_used)
    added = 0
    for ri, di, rc, dc, resolved in intervals:
        if resolved:
            continue
        raw = {}
        norm = {}
        for g in range(di, di + dc + 1):
            f = dev.fs[g]
            body = dev.body_at(g)
            raw.setdefault(hashlib.sha256(body).digest(), []).append(f)
            norm.setdefault(hashlib.sha256(_normalize(body)).digest(), []).append(f)
        pending = list(range(ri + 1, ri + rc))
        last = dev.fs[di]
        for g in pending:
            f = release.fs[g]
            body = release.body_at(g)
            cands = raw.get(hashlib.sha256(body).digest())
            if not cands or len(cands) != 1:
                cands = norm.get(hashlib.sha256(_normalize(body)).digest())
            if not cands or len(cands) != 1:
                continue
            if cands[0] in used or cands[0] <= last:
                continue
            mapping[f] = cands[0]
            used.add(cands[0])
            last = cands[0]
            added += 1
    return added


# ---------------------------------------------------------------------------
# Slide handling and resolution
# ---------------------------------------------------------------------------

PAGE = 0x4000


def detect_slide(release, addrs):
    """Pick the slide that lands the most addresses on release function starts.

    Runtime slides are page-aligned, which disambiguates cases where a handful of
    addresses happen to sit on function starts under more than one candidate.
    """
    if not addrs:
        return 0
    if all(release.image_lo <= a < release.image_hi for a in addrs):
        return 0                                    # already link-time addresses
    votes = Counter()
    for a in addrs:
        for f in release.fs:
            votes[a - f] += 1
    allowed = [s for s in votes
               if all(release.te_lo <= a - s < release.te_hi for a in addrs)]
    if not allowed:
        return None
    best = max(votes[s] for s in allowed)
    top = [s for s in allowed if votes[s] == best]
    aligned = [s for s in top if s > 0 and s % PAGE == 0]
    if len(aligned) == 1:
        return aligned[0]
    if len(top) == 1:
        return top[0]
    return None


def resolve(addr, release, dev, mapping):
    """Return (name, offset, exact) for an address in the release link space."""
    j = bisect.bisect_right(release.fs, addr) - 1
    if j < 0:
        return None, 0, False
    f = release.fs[j]
    d = mapping.get(f)
    if d is not None and d in dev.name_by_addr:
        return dev.name_by_addr[d], addr - f, True
    k = j
    while k >= 0:                                   # nearest preceding resolved
        f = release.fs[k]
        d = mapping.get(f)
        if d is not None and d in dev.name_by_addr:
            return dev.name_by_addr[d], addr - f, False
        k -= 1
    return None, 0, False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_addr(text):
    text = text.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return int(text, 16)


def parse_slide(text):
    text = str(text).strip()
    if text.lower() in ("auto", ""):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return int(text, 16)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Name addresses in the stripped RELEASE kernel by "
                    "transferring symbol names from a DEVELOPMENT kernel.")
    ap.add_argument("addresses", nargs="*",
                    help="release/runtime addresses to resolve (hex)")
    ap.add_argument("--release", default=RELEASE_PATH,
                    help="RELEASE Mach-O kernel (default: %(default)s)")
    ap.add_argument("--development", default=DEVELOPMENT_PATH,
                    help="DEVELOPMENT Mach-O kernel (default: %(default)s)")
    ap.add_argument("--slide", default="auto",
                    help="runtime->link slide (hex), '0', or 'auto' (default)")
    ap.add_argument("--stats", action="store_true",
                    help="print coverage statistics")
    ap.add_argument("--dump-cache", action="store_true",
                    help="write the release function map to %s" % CACHE_PATH)
    args = ap.parse_args(argv)

    release = Kernel(args.release)
    dev = Kernel(args.development)

    anchors, pinned, dropped = build_anchors(release, dev)
    mapping, intervals, resolved_i, skipped_i = build_mapping(release, dev, anchors)
    by_anchors = sum(1 for d in mapping.values() if d in dev.name_by_addr)
    content_added = content_fallback(release, dev, mapping, intervals,
                                     set(pinned.values()))
    ordered = sorted(mapping.items())
    monotonic = all(ordered[i][1] <= ordered[i + 1][1]
                    for i in range(len(ordered) - 1))
    for ra, da in pinned.items():           # name matches win over interval order
        mapping[ra] = da
    named = sum(1 for d in mapping.values() if d in dev.name_by_addr)

    addrs = [parse_addr(a) for a in args.addresses]
    slide = parse_slide(args.slide)
    slide_source = "forced" if slide is not None else "auto"
    if slide is None:
        slide = detect_slide(release, addrs)
        if slide is None:
            print("symmap: could not determine the runtime slide from the "
                  "supplied addresses; pass --slide HEX", file=sys.stderr)
            slide = 0
            slide_source = "none (assumed 0)"

    for addr in addrs:
        name, offset, exact = resolve(addr - slide, release, dev, mapping)
        if name is None:
            print("0x%016x  <unresolved>" % addr)
            continue
        suffix = " +0x%x" % offset if offset else ""
        gap = "" if exact else "  [gap]"
        print("0x%016x  %s%s%s" % (addr, name, suffix, gap))

    if args.stats:
        _print_stats(args, release, dev, anchors, pinned, dropped, intervals,
                     resolved_i, skipped_i, by_anchors, content_added, named,
                     slide, slide_source, monotonic)

    if args.dump_cache:
        _dump_cache(release, dev, mapping)
        print("symmap: wrote %s" % CACHE_PATH, file=sys.stderr)

    return 0


def _print_stats(args, release, dev, anchors, pinned, dropped, intervals,
                 resolved_i, skipped_i, by_anchors, content_added, named,
                 slide, slide_source, monotonic):
    total_i = len(intervals)
    coverage = 100.0 * named / len(release.fs) if release.fs else 0.0
    print("release kernel            : %s" % args.release)
    print("development kernel        : %s" % args.development)
    print("slide                     : 0x%x (%s)" % (slide, slide_source))
    print("release __TEXT_EXEC       : 0x%016x .. 0x%016x" %
          (release.te_lo, release.te_hi))
    print("release function starts   : %d" % len(release.fs))
    print("development function starts: %d" % len(dev.fs))
    print("release symbols (TEXT_EXEC): %d" % len(release.sym_by_name))
    print("development symbols        : %d" % len(dev.sym_by_name))
    print("anchors (name matches)     : %d (%d monotonic bounds, %d dropped)"
          % (len(pinned), len(anchors), dropped))
    print("intervals                  : %d total, %d 1:1, %d skipped"
          % (total_i, resolved_i, skipped_i))
    print("named by anchor mapping    : %d" % by_anchors)
    print("named by content fallback  : %d" % content_added)
    print("release functions named    : %d / %d (%.1f%%)"
          % (named, len(release.fs), coverage))
    print("interval mapping monotonic  : %s" % ("yes" if monotonic else "NO"))


def _dump_cache(release, dev, mapping):
    with open(CACHE_PATH, "w") as fh:
        for f in release.fs:
            d = mapping.get(f)
            if d is not None and d in dev.name_by_addr:
                fh.write("0x%016x %s\n" % (f, dev.name_by_addr[d]))


if __name__ == "__main__":
    sys.exit(main())
