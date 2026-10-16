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
| `043-70867-635.dmg.aea` | 11.27 GiB | **the root volume** (`OS` in the manifest), AEA-encrypted |
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

## The root volume is encrypted

`043-70867-635.dmg.aea` is an **AEA** (Apple Encrypted Archive). Its header
names the key source:

```
AEA1
  com.apple.wkms.url        https://wkms.sd.apple.com
  com.apple.wkms.auth-data  CqsEoZwYLKQ0wkJTzKAyrfy83Y6GJLOR0r8kyko...
```

so the archive's key comes from Apple's Web Key Management Service, which hands
it out as part of the device-bound restore flow. It is not derivable offline
from anything in the IPSW, and no key material ships as a member. Grabbing the
image is therefore necessary but not sufficient to read the root filesystem;
getting at its contents means either reproducing Apple's personalisation
against WKMS or providing the volume some other way.

The manifest's `Cryptex1,SystemOS` (also AEA) and the two plain APFS cryptexes
are the pieces of the root filesystem that Apple decrypts into place at boot.

## Extracting

```sh
URL=https://updates.cdn-apple.com/2026FallFCS/afcfc88e-bbe6-44bf-a5da-07c56eebc06c/UniversalMac_27.0_26A428_Restore.ipsw

# list members (optionally filtered)
python3 tools/ipsw_extract.py --url "$URL" --list --match .dmg

# pull one member to a path
python3 tools/ipsw_extract.py --url "$URL" --extract BuildManifest.plist --out /tmp/BM.plist

# kernel collection + root volume and the plain images
python3 tools/ipsw_extract.py --url "$URL" \
    --extract kernelcache.release.vma2 --out kernel/kernelcache.release.vma2
tools/grab_vmapple_rootfs.sh /mnt/windows2/vmapple-rootfs
```
