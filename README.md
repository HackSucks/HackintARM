# HackintARM

**Apple Silicon macOS on non-Apple AArch64 hardware.**

HackintARM boots the retail Apple Silicon kernel collection on machines Apple
never blessed: no QEMU `vmapple` machine model, no proprietary Apple hypervisor,
and eventually no emulator at all.

Today the macOS 27 "Golden Gate" VMApple kernel collection boots through
Gatehouse to `launchd` and a partial userland under QEMU `virt`. The frontier is
graphics: the machine has no display device, so the window server and the
services that depend on it cannot stay alive.

---

## Status

| Stage | State |
|---|---|
| UEFI application, serial console | done |
| Kernel collection load, slide, kext init | done |
| Apple Image4 / platform expert / GICv3 | done |
| IOKit matching, BSD init, MACF/AMFI | done |
| Storage transport and APFS root mount | done |
| `launchd`, mount phases, multi-user daemons | done |
| Graphical userland | **blocked on a display device** |
| Bare-metal AArch64 | after the QEMU `virt` target is complete |

The newest boot (`build/boot81.log`) reaches "Early boot complete. Continuing
system boot" and starts `loginwindow`, `WindowServer`, `opendirectoryd`,
`mDNSResponder`, `storagekitd`, `distnoted`, `PerfPowerService` and the rest of
the launchd job set. There is no kernel panic. `WindowServer`, `loginwindow`
and `timed` crash-loop ("Too many corpses being created") because there is no
GPU/display for them to bind to, and `ReportCrashService` cannot start either,
so the crashes leave no `.ips` reports.

The kernel-collection workarounds needed to get this far are in
[`gatehouse/src/patch.c`](gatehouse/src/patch.c). Each one is documented,
byte-verified against the staged copy, and applied only at load time; the
pristine image in `kernel/` is never modified.

### Milestones

- [x] UART/serial output
- [x] Kernel collection slides and all prelinked kexts load
- [x] Past `AppleImage4` platform initialisation
- [x] Full IOKit matching phase and BSD init
- [x] Root transport starts, APFS root volume mounts
- [x] `launchd` runs, mount phases complete, userland daemons start
- [ ] A display/GPU device the guest can bind
- [ ] A usable desktop
- [ ] Trestle on the boot path instead of QEMU's machine
- [ ] Real hardware

---

## The three sub-projects

HackintARM is an umbrella project. All three parts are bridge-themed.

| Sub-project | Role | Code |
|---|---|---|
| **Gatehouse** | The freestanding UEFI bootloader. Loads the kernel collection, builds the Apple Device Tree (ADT), supplies NVRAM, the trust cache and boot arguments, and jumps to XNU. Portable: the only board-specific input is the ADT description. | [`gatehouse/`](gatehouse/) |
| **Trestle** | The platform layer. Provides the AVP devices and services macOS expects — device tree, NVRAM, RTC, panic log, PCIe, and (soon) the graphics devices — on machines that do not implement Apple's paravirtual interfaces. | [`trestle/`](trestle/) |
| **Lantern** | The paravirtual GPU. Speaks VMApple's graphics protocol to the guest and translates it to a real GPU: Vulkan first, bare-metal GPU backends later. | [`docs/lantern.md`](docs/lantern.md) |

Trestle is designed to be machine-portable: device models never hard-code an
address; the machine description says where each device lives. That is what
lets the same models serve QEMU `virt` now and bare metal later.

### Lantern, in one paragraph

VMApple exposes graphics as two paravirtual devices (`paravirtualizedgraphics,gpu`
and `paravirtualizedgraphics,iosurface`) backed on real Apple hardware by
`ParavirtualizedGraphics.framework`. HackintARM cannot link that framework, so
Lantern replaces the host side. It reuses
[`steelbrain/reims-vgpu`](https://github.com/steelbrain/reims-vgpu) as the PVG
protocol core — a clean-room, framework-free implementation with a C API and a
swappable `Platform` backend — and adds only the device front-end, guest-memory
mapping and display sink. See **[`docs/lantern.md`](docs/lantern.md)** for the
architecture decision and bring-up plan.

---

## How a boot works

```
UEFI firmware
    │  BOOTAA64.EFI
    ▼
Gatehouse ── loads MH_FILESET, lays it out 1:1, applies kernel patches,
    │         builds the ADT, NVRAM, trust cache, boot arguments
    ▼
XNU (EL1) ── IOKit matching, BSD init, root media, APFS
    │
    ▼
launchd ── mount phases, daemons, loginwindow/WindowServer
    │
    ▼
Lantern ── paravirtual GPU + IOSurface devices → Vulkan → real display
```

The near-term target is under QEMU `virt`, with Gatehouse providing the ADT
itself. QEMU's generated device tree is not used for the guest's platform
description; the QEMU device placement and the ADT must agree, and both are
derived from the same machine description.

### Why the VMApple kernel collection

macOS 27 is Apple Silicon only, so there is no "legacy" kernel path left. The
VMApple collection is used because it makes far fewer assumptions about the
SoC than a bare-metal M-series collection: it expects a virtual platform with
paravirtual devices, which is exactly the platform Trestle is built to supply.
The collection on disk is the signed retail image and is never modified;
compatibility work happens in Gatehouse at load time, not in Apple's binaries.

---

## Bring-up machine

The current target is QEMU `virt` on an x86-64 host, using TCG (software CPU)
so that no Apple hardware is required to develop:

```sh
# Kernel collection at kernel/kernelcache.release.vma2.kc
./qemu/run.sh
```

Useful knobs (see the header of [`qemu/run.sh`](qemu/run.sh)):

| Variable | Meaning |
|---|---|
| `KERNEL=` | kernel collection to boot |
| `ROOTIMG=`, `ROOTFMT=` | root disk and its format (`raw` or `qcow2`) |
| `ISCIMG=`, `ISCFMT=` | auxiliary storage (iSC/xART container) |
| `TRUSTCACHE=` | static trust cache |
| `RAMDISK=`, `RAMDISKTC=` | restore ramdisk and its trust cache |
| `BOOTARGS=` | extra kernel arguments (inert unless set) |
| `INIT=`, `INITARG=` | PID 1 override for bring-up |
| `MEM=`, `CPU=` | guest RAM and CPU model |

The launcher builds Gatehouse, regenerates the ADT, stages an EFI System
Partition in `build/esp`, and starts QEMU with AAVMF, GICv3 and a GDB stub on
`:1234` (opt-in with `GDB=1`).

When `/mnt/windows2/combined2.qcow2` exists, the launcher uses it as the
read-write root disk by default. It is an overlay over `combined2.img`, which
keeps guest writes out of the base disk. `ROOTIMG`, `ROOTFMT` and `ROOTIMG_RO`
can select another image or access mode.

The QEMU `virt` machine is a development vehicle, not the destination. Once
Lantern and the remaining devices work there, only the machine description and
the GPU backend should change for bare metal.

---

## Disk tooling

The decrypted APFS volume is the input to disk assembly. The guest boots from
the resulting GPT disk, which carries the iSC partition and the APFS System,
Data and Preboot volumes; `qemu/run.sh` prefers its writable qcow2 overlay
when present. Nothing in the boot path retains AEA or an IPSW.

| Tool | Purpose |
|---|---|
| [`tools/ipsw_extract.py`](tools/ipsw_extract.py) | pull members out of an IPSW with HTTP Range requests |
| [`tools/im4p_extract.py`](tools/im4p_extract.py) | unwrap IMG4/IM4P payloads |
| [`tools/aea_decrypt.py`](tools/aea_decrypt.py) | decrypt the AEA root image to a raw APFS container |
| [`tools/mkisc`](tools/mkisc/) | build the iSC/xART auxiliary-storage container |
| [`tools/mkcombined`](tools/mkcombined/) | assemble System/Data/Preboot APFS volumes and a combined GPT disk |

`mkcombined` can build the single GPT disk macOS 27 expects (iSC partition 1,
main APFS container partition 2), inject the extracted dyld shared cache, and
populate the Data volume from the installer's `/System/Library/Templates/Data`.
The template matters: daemons such as `logd` assume its directory skeleton
exists, and their sandbox profiles do not allow creating the missing parents.

The restore image we use, its build identity and its member map are recorded in
[`docs/ipsw.md`](docs/ipsw.md). The detailed boot narrative — every wall hit on
the way to `launchd`, and the evidence for each fix — is in
[`docs/bringup.md`](docs/bringup.md).

---

## Requirements

For the eventual bare-metal target:

- AArch64 with ARMv8.2/8.3 extensions and **pointer authentication** (PAuth).
  SoCs without PAuth are not compatible for now.
- Support for **16 KiB pages** (or a CPU/MMU configuration that can run a
  16 KiB-page kernel).
- UEFI firmware, for Gatehouse.

For development on the QEMU `virt` target, any x86-64 or AArch64 host with QEMU
and EDK2 AAVMF works; no Apple hardware is needed.

---

## Repository layout

```
gatehouse/          UEFI bootloader (C + a little asm)
  dt/build_adt.py   builds the ADT blob handed to XNU
  src/patch.c       kernel-collection workarounds
trestle/            platform layer / hypervisor (in progress)
  src/              device models, ADT builder, machine descriptions
docs/               design and bring-up documentation
tools/              host-side helpers (IPSW, AEA, Mach-O, ADT, disk images)
qemu/               run.sh and GDB helpers for the QEMU virt target
kernel/             extracted Apple images (not in git)
```

New code for the GPU front-end will live under `lantern/` (device front-end,
QEMU integration, Trestle device model, platform backends).

---

## Documentation

- [`docs/lantern.md`](docs/lantern.md) — Lantern architecture, PVG device
  contract, and bring-up phases
- [`docs/bringup.md`](docs/bringup.md) — the detailed boot narrative
- [`docs/ipsw.md`](docs/ipsw.md) — the restore image and its contents
- [`trestle/docs/design.md`](trestle/docs/design.md) — Trestle's device-model
  architecture
- [`LICENSING.md`](LICENSING.md) — the mixed-licence policy

---

## Licence

Everything HackintARM authors is **GPL-2.0-or-later**. Acidanthera kexts are
GPL-3.0-or-later and combine with the core under GPLv3 terms. Linux
`GPL-2.0-only` code is kept isolated. The full policy is in
[`LICENSING.md`](LICENSING.md); the GPLv2 text is in [`LICENSE`](LICENSE).

Lantern vendors `reims-vgpu`, which is dual-licensed
`GPL-2.0-or-later OR LGPL-3.0-or-later`; the GPL option is compatible with this
tree.

---

## Roadmap

1. **Lantern device probe** — publish the GPU and IOSurface nodes; bring the
   MMIO register file, interrupts and guest-memory map up under QEMU `virt`.
2. **PVG protocol** — FIFOs, resources, textures and command streams over
   Vulkan via reims-vgpu's `Platform` backend.
3. **Scanout** — frames reach a real window and QMP `screendump`; `WindowServer`
   and `loginwindow` stay alive.
4. **Trestle** — move the same device models onto the boot path, replacing
   QEMU's machine description.
5. **Bare metal** — EFI + Trestle + a native GPU backend, with only the
   `Platform` and machine description differing.

There is no reliable ETA. The boot-to-userland stage is done; the desktop and
bare metal are large, device-specific projects.
