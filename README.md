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
legitimate Apple IPSW (`tools/ipsw_extract.py`, `tools/im4p_extract.py`).

## Licence

GPL-2.0-or-later for everything HackintARM authors; third-party Acidanthera
kexts are GPL-3.0-or-later and combine with the core under GPLv3 terms. Linux
`GPL-2.0-only` code is kept isolated. The full policy is in
[`LICENSING.md`](LICENSING.md); the GPLv2 text is in [`LICENSE`](LICENSE).

## Status

Gatehouse boot support for the `MH_FILESET` kernel collection works: the kernel
slides, initialises its prelinked kexts and registers its IOKit personalities.
Bring-up is currently pushing through early platform init (the ADT nodes
AppleImage4 and the platform "mpo" policy require).
