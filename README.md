# HackintARM

Boot Apple Silicon macOS on real AArch64 hardware — no QEMU `vmapple` machine
model, no proprietary Apple hypervisor.

Two pieces:

* **Gatehouse** — a freestanding UEFI bootloader (`gatehouse/`). It loads an
  XNU kernel collection (an `MH_FILESET`), lays it out 1:1 flat, synthesises the
  Apple Device Tree (ADT) that XNU expects, and hands control to the kernel. It
  is machine-portable: the only thing that ties it to a board is the ADT it
  builds (`gatehouse/dt/build_adt.py`).
* **Trestle** — a hypervisor (`trestle/`, in progress). It provides the
  virtualised platform the guest expects on hardware that does not implement
  Apple's paravirtual AVP/CTRR interfaces directly.

The near-term bring-up target is macOS 27 "Golden Gate" (VMApple kernel
collection) running under Gatehouse on QEMU `virt`; the ultimate target is real
bare-metal AArch64.

## Layout

```
gatehouse/          UEFI bootloader (C + a little asm)
  dt/build_adt.py   builds the ADT blob handed to XNU
  src/, include/
trestle/            hypervisor (in progress)
tools/              host-side helpers (ADT/Mach-O/im4p/pbzx inspection)
qemu/               run.sh + GDB scripts for the QEMU virt bring-up
kernel/             extracted Apple images (NOT in git — see LICENSING.md)
```

## Booting under QEMU

`qemu/run.sh` stages an EFI System Partition from `gatehouse/` and `kernel/`,
then launches QEMU `virt` with AAVMF and a GICv3, with a GDB stub on `:1234`.

```sh
# put an extracted VMApple kernel collection at kernel/kernelcache.release.vma2.kc
KERNEL=kernel/kernelcache.release.vma2.kc GDB=0 ./qemu/run.sh
```

`kernel/` is not distributed with this repo; extract the images from a
legitimate Apple IPSW (`tools/ipsw_extract.py`, `tools/im4p_extract.py`). The
restore image we use, its build identity, and the member map are in
[`docs/ipsw.md`](docs/ipsw.md).

## Licence

GPL-2.0-or-later for everything HackintARM authors; third-party Acidanthera
kexts are GPL-3.0-or-later and combine with the core under GPLv3 terms. Linux
`GPL-2.0-only` code is kept isolated. The full policy is in
[`LICENSING.md`](LICENSING.md); the GPLv2 text is in [`LICENSE`](LICENSE).

## Status

Gatehouse boots the `MH_FILESET` kernel collection: the kernel slides,
initialises its prelinked kexts and registers its IOKit personalities.

The ADT supplies the machine identity, boot-manifest and chip/secure-boot nodes
the early kernel requires (`/product`, `/options`, `/defaults`, `/chosen` with
`manifest-properties`/`asmb`, the `crypto-hash-method` set, and the NVRAM
image), taken from the authentic VMApple ADT.

Walls cleared so far:

* **ADT machine identity** — byte-faithful `/product`, `/options`, `/defaults`,
  `/chosen/manifest-properties`, `/chosen/asmb`.
* **NVRAM** — the kernel picks its handler from the store's contents, so it
  needs a **V3 image** on `/chosen` (`nvram-proxy-data`) plus the geometry and
  `nvram-raw` flag, not the CHRP partitions the open-source driver documents.
* **Image4 crypto** — AppleImage4 reads `/chosen` `crypto-hash-method`
  (`"sha2-384"`).
* **Platform expert** — the root nub is named from the device tree root's
  `compatible`; it must publish `AppleVirtualPlatformARM` so
  `AppleVirtualPlatformARMPE` matches.

Bring-up now loads the full kext set (`AppleARMPlatform`,
`AppleVirtualPlatform`, `AppleVirtIO*`, `IOTimeSyncFamily`, `IOgPTPPlugin`, …)
with **no panic**. It then stalls in late service startup on repeated
`Kext com.apple.driver.AppleARMPlatform is already loaded` — the stage right
before it would go looking for a root volume to mount.

The root volume itself is `043-70867-635.dmg.aea` in the IPSW, an
**AEA-encrypted** image whose key comes from Apple's WKMS during the
device-bound restore flow (see [`docs/ipsw.md`](docs/ipsw.md)); it is being
grabbed to `/mnt/windows2` so that the mount path can be developed against it,
but reading it needs the restore key or a substitute volume.

The remaining platform devices (NVRAM, timers, GIC routing) are virtio/AAPL
devices that Trestle is meant to emulate.
