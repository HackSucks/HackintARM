#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
tools/aea_decrypt.py - turn an IPSW `.dmg.aea` back into a raw DMG.

Since macOS 15 / iOS 18 Apple ships the root filesystem inside IPSWs as an
Apple Encrypted Archive (.dmg.aea), profile 1 (AES-CTR + HMAC-SHA256, no
signature), instead of a plain DMG.  The archive is not device-bound: its auth
data names a public key service, and the 32-byte symmetric key is delivered
HPKE-wrapped, so the file can be decrypted without a device.

The format (all integers little-endian):

    prologue   "AEA1"                 u32 magic
               u32 profile            (1 = symmetric)
               u32 auth_data_len
               auth_data[auth_data_len]   length-prefixed "key\\0value" fields
               u8  main_salt[32]
               u8  root_hmac[32]
               u8  root_data[48]          AES-CTR, key = HKDF(main_key, "AEA_RHEK")
               u8  cluster_hmac[32]       HMAC of the previous cluster
    then `clusters` of:
               enc_segment_headers[seg_hdr_size * segs_per_cluster]
               next_cluster_hmac[32]
               segment_hmacs[32 * segs_per_cluster]
               <segment payloads, back to back>

`main_key = HKDF(sym_key, main_salt, "AEA_AMK" + u32(profile))`, and the root
header authenticates `root_data` against `cluster_hmac || auth_data`.  Each
segment is authenticated, decrypted, optionally LZFSE/LZBITMAP/zlib-decompressed
and checksummed, then written at `cluster * seg_size * segs_per_cluster +
index * seg_size`.

Keys:
  * `--key-value base64:...` if you already have the symmetric key, or
  * `--fcs` to derive it from the archive: the auth data carries
    `com.apple.wkms.fcs-key-url` (a public PEM on Apple's CDN) and an HPKE
    (DHKEM P-256 / HKDF-SHA256 / AES-256-GCM) `enc-request` + `wrapped-key`.

Input may be a local file (`--in`) or the IPSW over HTTP (`--url`), in which
case only the wanted member is Range-fetched.  Reads are strictly sequential,
so the encrypted archive never has to be stored: it streams into the decrypted
DMG, whose size (from the root header) is the only thing that must fit on disk.

    aea_decrypt.py --url <ipsw> --member 043-70867-635.dmg.aea --fcs --out root.dmg
    aea_decrypt.py --in 043-70867-635.dmg.aea --fcs --out root.dmg
    aea_decrypt.py --url <ipsw> --member 043-70867-635.dmg.aea --fcs --info
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.request

MAGIC = b"AEA1"
PROFILE_SYMMETRIC = 1

# AEA key-derivation labels
K_MAIN = b"AEA_AMK"
K_ROOTHDR = b"AEA_RHEK"
K_CLUSTER = b"AEA_CK"
K_CLUSTER_HDR = b"AEA_CHEK"
K_SEGMENT = b"AEA_SK"
K_PADDING = b"AEA_PAK"

# checksum types
CK_NONE, CK_MURMUR, CK_SHA256 = 0, 1, 2
CK_SIZE = {CK_NONE: 0, CK_MURMUR: 8, CK_SHA256: 32}

# compression ids
COMP_NONE, COMP_LZ4, COMP_LZBITMAP = ord("-"), ord("4"), ord("b")
COMP_LZFSE, COMP_LZVN, COMP_LZMA, COMP_ZLIB = ord("e"), ord("f"), ord("x"), ord("z")


# --------------------------------------------------------------------------
# key schedule primitives
# --------------------------------------------------------------------------

def hkdf(ikm, salt, info, length):
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def hmac_ad(key, data, ad):
    """Apple's HMAC-with-associated-data: HMAC(key, ad || data || le64(len(ad)))."""
    return hmac.new(key, ad + data + struct.pack("<Q", len(ad)), hashlib.sha256).digest()


def parse_auth_data(ad):
    fields, off = {}, 0
    while off < len(ad):
        size = struct.unpack_from("<I", ad, off)[0]
        blob = ad[off:off + size]
        nul = blob.index(b"\x00", 4)
        fields[blob[4:nul].decode()] = blob[nul + 1:].decode("utf-8", "replace")
        off += size
    return fields


def fcs_symmetric_key(fields, verbose=False):
    """Derive the symmetric key from the archive's WKMS/FCS auth data."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, load_pem_private_key)

    resp = json.loads(fields["com.apple.wkms.fcs-response"])
    enc = base64.b64decode(resp["enc-request"])
    wrapped = base64.b64decode(resp["wrapped-key"])
    url = fields["com.apple.wkms.fcs-key-url"]
    if verbose:
        print("  fcs-key-url: %s" % url)

    pem = urllib.request.urlopen(url, timeout=60).read()
    sk = load_pem_private_key(pem, password=None)
    pkr = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    # RFC 9180 base mode: DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM
    kem_id, kdf_id, aead_id = 0x0010, 0x0001, 0x0002
    s_kem = b"KEM" + struct.pack(">H", kem_id)
    s_hpke = b"HPKE" + struct.pack(">HHH", kem_id, kdf_id, aead_id)

    def labeled_extract(salt, suite, label, ikm):
        prk = hmac.new(salt or b"\x00" * 32, b"HPKE-v1" + suite + label + ikm,
                       hashlib.sha256).digest()
        return prk

    def labeled_expand(prk, suite, label, info, length):
        labeled_info = struct.pack(">H", length) + b"HPKE-v1" + suite + label + info
        out, t, i = b"", b"", 1
        while len(out) < length:
            t = hmac.new(prk, t + labeled_info + bytes([i]), hashlib.sha256).digest()
            out += t
            i += 1
        return out[:length]

    pk_e = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), enc)
    dh = sk.exchange(ec.ECDH(), pk_e)
    eae_prk = labeled_extract(b"", s_kem, b"eae_prk", dh)
    shared = labeled_expand(eae_prk, s_kem, b"shared_secret", enc + pkr, 32)

    psk_id_hash = labeled_extract(b"", s_hpke, b"psk_id_hash", b"")
    info_hash = labeled_extract(b"", s_hpke, b"info_hash", b"")
    ksc = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(shared, s_hpke, b"secret", b"")
    key = labeled_expand(secret, s_hpke, b"key", ksc, 32)
    nonce = labeled_expand(secret, s_hpke, b"base_nonce", ksc, 12)
    return AESGCM(key).decrypt(nonce, wrapped, b"")


# --------------------------------------------------------------------------
# byte sources: local file or sequential HTTP Range reader
# --------------------------------------------------------------------------

def http_fetch(url, start, end, retries=6):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"Range": "bytes=%d-%d" % (start, end)})
            with urllib.request.urlopen(req, timeout=180) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(min(2 ** attempt, 20))
    raise last


class HTTPMemberReader:
    """Sequential reader over one IPSW member, Range-fetched in big chunks."""

    def __init__(self, url, member, chunk=32 << 20):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import ipsw_extract as ix
        self._ix = ix
        size = ix.content_length(url)
        cd_off, cd_size, _ = ix.zip64_directory(url, size)
        cd = ix.fetch(url, cd_off, cd_off + cd_size - 1)
        hits = [m for m in ix.parse_central_directory(cd) if m["name"] == member]
        if not hits:
            raise SystemExit("no such IPSW member: %s" % member)
        m = hits[0]
        if m["method"] != 0:
            raise SystemExit("member %s is deflated; extract it first" % member)
        self.url = url
        self.base = ix.data_offset(url, m)
        self.size = m["csize"]
        self.chunk = chunk
        self.pos = 0
        self.buf = b""

    def read(self, n):
        while len(self.buf) < n:
            if self.pos + len(self.buf) >= self.size:
                raise EOFError("short read from IPSW member")
            end = min(self.pos + len(self.buf) + self.chunk, self.size) - 1
            self.buf += http_fetch(self.url, self.base + self.pos + len(self.buf), self.base + end)
        out, self.buf = self.buf[:n], self.buf[n:]
        self.pos += n
        return out


class FileReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.pos = 0
        self.size = os.path.getsize(path)

    def read(self, n):
        out = self.f.read(n)
        if len(out) != n:
            raise EOFError("short read from %s" % self.f.name)
        self.pos += n
        return out

    def skip(self, n):
        self.f.seek(n, os.SEEK_CUR)
        self.pos += n


# --------------------------------------------------------------------------
# decryption
# --------------------------------------------------------------------------

def _aes_ctr(key, iv, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor().update(data)


def _lzfse(data, lib=None):
    """LZFSE / LZBITMAP decode, via the `lzfse` module or liblzfse.so."""
    try:
        import lzfse
        return lzfse.decompress(data)
    except ImportError:
        pass
    import ctypes
    path = lib or "liblzfse.so"
    dll = ctypes.CDLL(path)
    # lzfse_decode_buffer(dst, dst_size, src, src_size, scratch) == decoded size
    for size in (1 << 25, 1 << 28):
        dst = ctypes.create_string_buffer(size)
        got = dll.lzfse_decode_buffer(dst, ctypes.c_size_t(size),
                                      data, ctypes.c_size_t(len(data)), None)
        if got != 0:
            return dst.raw[:got]
    raise SystemExit("lzfse decompression failed (no `lzfse` module and no liblzfse.so)")


def _decompress(data, comp, out_size):
    if comp == COMP_NONE:
        return data
    if comp in (COMP_LZFSE, COMP_LZBITMAP):
        return _lzfse(data)
    if comp == COMP_ZLIB:
        import zlib
        return zlib.decompress(data)
    raise SystemExit("unsupported AEA compression %r" % chr(comp))


def decrypt(src, out_path, key, info_only=False, verbose=True, limit=0):
    head = src.read(12)
    magic, profile, alen = struct.unpack_from("<4sII", head, 0)
    if magic != MAGIC:
        raise SystemExit("not an AEA file (magic %r)" % magic)
    if profile != PROFILE_SYMMETRIC:
        raise SystemExit("unsupported AEA profile %d" % profile)
    auth_data = src.read(alen)
    fields = parse_auth_data(auth_data)
    if verbose:
        print("AEA profile %d, auth data %d bytes, %d fields" % (profile, alen, len(fields)))

    if key is None:
        key = fcs_symmetric_key(fields, verbose=verbose)
        if verbose:
            print("  symmetric key (hashed): %s..." % hashlib.sha256(key).hexdigest()[:16])

    main_salt = src.read(32)
    main_key = hkdf(key, main_salt, K_MAIN + struct.pack("<I", profile), 32)

    root_hmac = src.read(32)
    root_data = src.read(48)
    cluster_hmac = src.read(32)
    rk = hkdf(main_key, b"", K_ROOTHDR, 80)
    if not hmac.compare_digest(hmac_ad(rk[:32], root_data, cluster_hmac + auth_data), root_hmac):
        raise SystemExit("root header HMAC mismatch (wrong key?)")
    rh = _aes_ctr(rk[32:64], rk[64:80], root_data + auth_data)
    file_size, enc_size, seg_size, segs_per_cluster, comp, checksum = \
        struct.unpack_from("<QQIIBB", rh, 0)
    seg_hdr_size = CK_SIZE[checksum] + 8

    if verbose or info_only:
        print("root header verified:")
        print("  file size        : %d (%.2f GiB)" % (file_size, file_size / 2**30))
        print("  segment size     : %d, %d segments/cluster" % (seg_size, segs_per_cluster))
        print("  compression      : %r, checksum %d" % (chr(comp), checksum))
        print("  source bytes     : %d" % enc_size)
    if info_only:
        return

    clusters = (file_size + seg_size * segs_per_cluster - 1) // (seg_size * segs_per_cluster)
    target = min(file_size, limit) if limit else file_size
    # Written strictly sequentially (positions are monotonic); gaps are padded
    # with zeros rather than preallocating with truncate(), which not every
    # filesystem accepts at these sizes.
    out = open(out_path, "wb")
    written = 0
    t0 = time.time()
    stop = False
    for cindex in range(clusters):
        cluster_key = hkdf(main_key, b"", K_CLUSTER + struct.pack("<I", cindex), 32)
        chk = hkdf(cluster_key, b"", K_CLUSTER_HDR, 80)

        enc_hdrs = src.read(seg_hdr_size * segs_per_cluster)
        next_cluster_mac = src.read(32)
        seg_mac_data = src.read(32 * segs_per_cluster)

        calc = hmac_ad(chk[:32], enc_hdrs, next_cluster_mac + seg_mac_data)
        if not hmac.compare_digest(calc, cluster_hmac):
            raise SystemExit("cluster %d HMAC mismatch" % cindex)
        hdr_data = _aes_ctr(chk[32:64], chk[64:80], enc_hdrs)

        seg_hdrs = []
        for idx in range(segs_per_cluster):
            dsz, csz, ck = struct.unpack_from("<II32s", hdr_data, idx * seg_hdr_size)
            seg_hdrs.append((dsz, csz, ck))
        seg_macs = [seg_mac_data[i * 32:i * 32 + 32] for i in range(segs_per_cluster)]

        for idx, (dsz, csz, ck) in enumerate(seg_hdrs):
            if dsz == 0:
                continue
            seg = src.read(csz)
            sk = hkdf(cluster_key, b"", K_SEGMENT + struct.pack("<I", idx), 80)
            if not hmac.compare_digest(hmac_ad(sk[:32], seg, b""), seg_macs[idx]):
                raise SystemExit("segment %d/%d HMAC mismatch" % (cindex, idx))
            plain = _aes_ctr(sk[32:64], sk[64:80], seg)
            if dsz != csz:
                plain = _decompress(plain, comp, dsz)
            if len(plain) != dsz:
                raise SystemExit("segment %d/%d size %d != %d" % (cindex, idx, len(plain), dsz))
            if checksum == CK_SHA256 and hashlib.sha256(plain).digest() != ck:
                raise SystemExit("segment %d/%d SHA-256 mismatch" % (cindex, idx))
            pos = cindex * seg_size * segs_per_cluster + idx * seg_size
            if pos > written:                     # gap / sparse region
                out.write(b"\x00" * min(pos - written, target - written))
                written = min(pos, target)
            if written < target:
                out.write(plain[:target - written])
                written += min(len(plain), target - written)
            if written >= target:
                stop = True
                break

        cluster_hmac = next_cluster_mac
        pct = 100.0 * written / target
        print("  cluster %2d/%d  %6.2f%%  %d/%d  (%.1f MiB/s)"
              % (cindex + 1, clusters, pct, written, target,
                 (written / (1 << 20)) / max(time.time() - t0, 1e-6)),
              end="\r", flush=True)
        if stop or written >= target:
            break
    if written < target:                          # trailing gap
        out.write(b"\x00" * (target - written))
        written = target
    print()
    out.close()
    got = os.path.getsize(out_path)
    if got != target:
        raise SystemExit("output size %d != expected %d" % (got, target))
    print("wrote %s (%d bytes)" % (out_path, got))


def parse_key(s):
    if s.startswith("base64:"):
        return base64.b64decode(s[7:])
    if s.startswith("hex:"):
        return bytes.fromhex(s[4:])
    for dec in (base64.b64decode, bytes.fromhex):
        try:
            k = dec(s)
            if len(k) == 32:
                return k
        except Exception:  # noqa: BLE001
            pass
    raise SystemExit("cannot interpret --key-value")


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="IPSW URL (member Range-fetched)")
    src.add_argument("--in", dest="infile", help="local .dmg.aea file")
    ap.add_argument("--member", help="IPSW member name (with --url)")
    ap.add_argument("--out", help="decrypted DMG path")
    ap.add_argument("--key-value", help="'base64:...' / 'hex:...' symmetric key")
    ap.add_argument("--fcs", action="store_true", help="derive the key from the auth data")
    ap.add_argument("--info", action="store_true", help="print the root header and stop")
    ap.add_argument("--limit", type=int, default=0,
                    help="produce only the first N bytes of output (probe)")
    args = ap.parse_args()

    if args.url:
        if not args.member:
            raise SystemExit("--member is required with --url")
        reader = HTTPMemberReader(args.url, args.member)
    else:
        reader = FileReader(args.infile)

    key = parse_key(args.key_value) if args.key_value else None
    if key is None and not args.fcs:
        raise SystemExit("need --fcs or --key-value")
    if not args.info and not args.out:
        raise SystemExit("--out is required unless --info")

    decrypt(reader, args.out, key, info_only=args.info, limit=args.limit)


if __name__ == "__main__":
    main()
