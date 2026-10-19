# The macOS 27 restore image

Everything Gatehouse loads comes out of Apple's restore image (IPSW). This file
records which one we use, why, and what is inside it, so the mapping does not
have to be re-derived.

## Identity

The kernel collection in `kernel/` is Darwin 27.0.0
(`root:xnu-13432.1.9~1/RELEASE_ARM64_VMAPPLE`), build **26A428**. The matching
restore image is:

| | |
|---|---|
| release | macOS 27.0 "Golden Gate" |
| build | 26A428 (kernel `xnu-13432.1.9`) |
| device class | `vma2macosap` (`VirtualMac2,1`, "Apple Virtual Machine 1") |
| URL | `https://updates.cdn-apple.com/2026FallFCS/afcfc88e-bbe6-44bf-a5da-07c56eebc06c/UniversalMac_27.0_26A428_Restore.ipsw` |
| size | 26,626,436,228 bytes, 1630 members |

macOS 27.0.1 (build 26A434) is a *different* IPSW; it does not match this kernel
collection.

`BuildManifest.plist` (extracted with `tools/ipsw_extract.py`) carries three
`vma2macosap` identities, all build 26A428.

## Members we use

Apple ships the archive as a zip64 with a ~169 KiB central directory near the
end, so a member can be pulled with a handful of HTTP Range requests instead of
downloading 25 GiB. `tools/ipsw_extract.py` does this; it streams large members
straight to disk and resumes a partial stored member on a re-run.

| member | size | role |
|---|---|---|
| `kernelcache.release.vma2` | ~22 MiB | the kernel collection (XNU + prelinked kexts) gatehouse loads |
| `BuildManifest.plist` | 31 MiB | identity/member table |
| `043-70867-635.dmg.aea` | 11.27 GiB | **the root volume** (`OS`), AEA profile 1 (decryptable — see below) |
| `Firmware/043-70867-635.dmg.aea.trustcache` | 441,049 B | **the root volume's static trust cache** (IMG4 `trst`, see below) |
| `094-86031-269.dmg` | 7.71 GiB | `Cryptex1,RosettaOS` — plain raw APFS image |
| `043-70637-685.dmg` | 54 MiB | `Cryptex1,AppOS` — plain raw APFS image |
| `043-70833-682.dmg` | 373 MiB | `RestoreRamDisk` — IM4P-wrapped payload |
| `043-70842-681.dmg` | 386 MiB | IM4P-wrapped payload |
| `022-20292-673.dmg.aea` | 1.31 GiB | `BaseSystem` (recovery), AEA |
| `043-70701-646.dmg.aea` | 2.42 GiB | `Cryptex1,SystemOS`, AEA |

`tools/grab_vmapple_rootfs.sh` fetches the root volume together with the plain
images into a destination directory (default `/mnt/windows2/vmapple-rootfs`).

Note that several manifest entries point at `*.dmg` names whose contents are not
UDIF disk images:

* the plain ones with an `NXSB` superblock at offset 32 are **raw APFS
  containers** (they can be walked directly, no `hdiutil`);
* the ones beginning `30 84 .. .. 00 15 16 04 49 4d 34 50` (`IM4P`) are
  **IMG4 payloads** and must be unwrapped first (`tools/im4p_extract.py`).

## The root volume is an encrypted APFS image

`043-70867-635.dmg.aea` is an **AEA** (Apple Encrypted Archive), profile 1
(AES-CTR + HMAC-SHA256, no signature). It is the only copy of the root volume:
the manifest has no plain DMG of `OS`, and the plain members above are the
restore ramdisk and the cryptexes, not the root.

The archive is **not device-bound**, so it can be decrypted here. Its auth data
carries the key-delivery parameters:

```
com.apple.wkms.url          https://wkms.sd.apple.com
com.apple.wkms.auth-data    <base64>
com.apple.wkms.fcs-response {"enc-request": <HPKE enc>, "wrapped-key": <HPKE ct>}
com.apple.wkms.fcs-key-url  https://wkms-public.apple.com/fcs-keys/<id>= ->
                            https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/<id>=
```

The key URL is a public PEM (a P-256 private key on Apple's CDN). The 32-byte
symmetric key is HPKE-sealed (`DHKEM(P-256, HKDF-SHA256)` + `HKDF-SHA256` +
`AES-256-GCM`, RFC 9180 base mode) to it, so decrypting needs only that fetch —
no device, no personalisation:

`tools/aea_decrypt.py --fcs` does this and streams the AEA out of the IPSW while
decrypting it, so the encrypted copy is never written to disk.

What comes out is **not** a UDIF `.dmg` but a **raw APFS container** — which is
exactly the raw block-device image macOS wants (`NXSB`, 4 KiB blocks):

```
profile          1 (symmetric)
inner size       14,189,330,432 bytes (13.21 GiB)
segment size     1 MiB, 256 segments/cluster, 53 clusters
compression      LZFSE
checksum         SHA-256
```

Decrypting needs a Python with `cryptography` and an LZFSE decoder (`lzfse`,
or `liblzfse.so`):

```sh
python3 -m venv .venv && .venv/bin/pip install cryptography lzfse
PYTHON=.venv/bin/python tools/grab_vmapple_rootfs.sh /mnt/windows2/vmapple-rootfs
```

`Cryptex1,SystemOS` (2.42 GiB) and `BaseSystem` (1.31 GiB) are AEA of the same
shape and decrypt the same way; the two plain APFS cryptexes are the pieces of
the root filesystem Apple mounts into place at boot.

## The static trust cache

Every disk image in the restore image has a matching `Firmware/<name>.trustcache`
member (441,049 bytes for the root volume, 23,411 for the restore ramdisk, ...).
It is the set of cdhashes the boot chain is willing to treat as **platform
binaries**, and macOS 27 refuses to execute `launchd` without it:

```
AMFI: /sbin/launchd: Rejecting signature, binary has platform identifier but
      is not in the trustcache
AMFI: hook..execve() killing init (pid 1): Attempt to execute completely
      unsigned code (must be at least ad-hoc signed).
```

(`amfi_get_out_of_my_way=1` does not relax this on 26A428; the platform-identifier
policy is not boot-arg controlled.)

The member is not a raw structure but an **IMG4** wrapper, which is what iBoot
verifies and then hands over as a payload:

```
30 83 06ba d4           SEQ
  16 04 "IM4P"          16 04 "trst"          16 01 "1"
  04 83 06ba c0         OCTET STRING (441,024 bytes)
    02 00 00 00         version 2
    26 49 6f 5f ...     uuid[16]
    c7 47 00 00         count = 18,375
    ...                 18,375 entries of 24 bytes (24 + 18375*24 = 441,024)
```

XNU finds it through the device tree, exactly where iBoot puts it:

* `/chosen/memory-map/TrustCache` -- a **16-byte** property, `(base, length)`,
  the physical region holding the payload. `kern_trustcache.c` checks the
  property size (`Unexpected /chosen/memory-map/TrustCache property size %u !=
  %zu`), range-checks the region and copies the entries out. The authentic
  static tree has only zeroed `MemoryMapReserved-N` placeholders; the named
  entries are iBoot runtime additions, so a loader that plays iBoot has to add
  this one itself.
* `/osenvironments/<env>/amfi-allows-trust-cache-load` selects whether
  *additional* (loadable) trust caches may be loaded later; it does not
  substitute for the static one.

## Extracting

```sh
URL=https://updates.cdn-apple.com/2026FallFCS/afcfc88e-bbe6-44bf-a5da-07c56eebc06c/UniversalMac_27.0_26A428_Restore.ipsw

# list members (optionally filtered)
python3 tools/ipsw_extract.py --url "$URL" --list --match .dmg

# pull one member to a path
python3 tools/ipsw_extract.py --url "$URL" --extract BuildManifest.plist --out /tmp/BM.plist

# the kernel collection
python3 tools/ipsw_extract.py --url "$URL" \
    --extract kernelcache.release.vma2 --out kernel/kernelcache.release.vma2

# the root volume (decrypted) plus the plain images
PYTHON=.venv/bin/python tools/grab_vmapple_rootfs.sh /mnt/windows2/vmapple-rootfs

# just look at the root volume's header, without downloading the whole thing
.venv/bin/python tools/aea_decrypt.py --url "$URL" \
    --member 043-70867-635.dmg.aea --fcs --info
```

