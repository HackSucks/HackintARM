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
tools/              host-side helpers (ADT/Mach-O/im4p/pbzx/IPSW/AEA)
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
with **no panic**, then goes quiet after the last kext, with the serial
repeating `Kext com.apple.driver.AppleARMPlatform is already loaded`.

Under GDB the guest is not faulted — it is executing, and the boot thread is
inside `_thread_block` (the scheduler's block path) around a
`mach_absolute_time`-style read of `CNTVCT_EL0` paired with a per-CPU timebase
offset, with `CNTFRQ_EL0` = 1 GHz and the virtual timer armed
(`CNTV_CTL_EL0` = 1). So it is waiting on time / a platform event rather than
crashing, which is exactly where the remaining platform devices (NVRAM, timers,
interrupt routing) and a root volume have to actually exist.

The root volume itself is `043-70867-635.dmg.aea` in the IPSW. It is an AEA
(profile 1) archive, but it is **not** device-bound: its auth data names a
public PEM and an HPKE-wrapped key, so `tools/aea_decrypt.py` decrypts it while
Range-fetching it from Apple's CDN, producing a raw APFS container
(`NXSB`, 13.21 GiB) — the raw block device macOS wants. See
[`docs/ipsw.md`](docs/ipsw.md).

The remaining platform devices (NVRAM, timers, GIC routing) are virtio/AAPL
devices that Trestle is meant to emulate.
