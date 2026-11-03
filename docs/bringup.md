# Bring-up log

This is the detailed narrative of the boot bring-up: every wall the project hit
on the way from the first UART byte to `launchd`, and the evidence behind each
fix. The top-level [`README.md`](../README.md) is the summary; this file keeps
the long version so the reasoning does not have to be rediscovered.

The target is macOS 27 "Golden Gate" (VMApple kernel collection) running under
Gatehouse on QEMU `virt`; the ultimate target is real bare-metal AArch64.

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
./qemu/run.sh
```

The launcher defaults to that kernel collection. `KERNEL=/path/to/other.kc`
overrides it; the image has to be a collection, not a bare kernel slice.

`kernel/` is not distributed with this repo; extract the images from a
legitimate Apple IPSW (`tools/ipsw_extract.py`, `tools/im4p_extract.py`). The
restore image we use, its build identity, and the member map are in
[`docs/ipsw.md`](ipsw.md).

## Running with EL2 (Trestle)

Trestle needs EL2. Pass `VIRT_EXTRA=virtualization=on`:

```sh
VIRT_EXTRA=virtualization=on ./qemu/run.sh
```

With the virtualization extensions enabled, firmware is entered at EL2 and runs
in VHE host mode, servicing its own interrupts there. Pulling UEFI down to EL1
mid-boot fights that live exception state, so Gatehouse does not: it runs at the
firmware's EL and only touches EL2 in `gh_jump_to_kernel`, at the final handoff,
when Boot Services are gone. It disables the firmware's `SCTLR_EL2` (VHE), sets
`HCR_EL2`, installs Trestle's vectors and stack, and `eret`s to XNU at EL1h.
The same path works on hardware; only the way the loader obtains EL2 differs.

Two things learned the hard way and worth keeping in mind:

* **Pointer authentication must be enabled for EL1.** When EL2 is enabled and
  `HCR_EL2.API` is 0, every PAC instruction at EL1 is architecturally
  UNDEFINED. XNU's first `pacibsp` then lands in Trestle's vector table as
  EC `0x09`. `HCR_EL2` therefore carries `{APK,API}` in addition to `RW`.
* **The vector layout depends on `HCR_EL2.E2H`.** Trestle runs with `E2H=0`,
  so lower-EL AArch64 traps arrive at `VBAR_EL2 + 0x400`, not `+0x200` (the
  latter is the current-EL/SPx group). Getting this wrong sends every HVC to
  the dead-end handler.

The emulated CPU is also matched to the target SoC: `max,sve=off,sme=off`. An
Apple T8103 has neither SVE nor SME; with QEMU's defaults XNU probes the SME
control registers (`SMCR_EL1`/`SMPRI_EL1`), which trap to EL2 and would tempt
it into code paths the real machine cannot execute.

With both changes, XNU runs at EL1 under Trestle and boots the full disk to
`Early boot complete`, then to a `loginwindow` crash-loop -- the same frontier
as the EL1 boot, which is display/GPU work (see [`lantern.md`](lantern.md)).

## Licence

GPL-2.0-or-later for everything HackintARM authors; third-party Acidanthera
kexts are GPL-3.0-or-later and combine with the core under GPLv3 terms. Linux
`GPL-2.0-only` code is kept isolated. The full policy is in
[`LICENSING.md`](../LICENSING.md); the GPLv2 text is in [`LICENSE`](../LICENSE).

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
* **GICv3 redistributor** — `AppleARMGICv3.cpp:182` panics with
  *"Redistributor region size is not multiple of 128K"* unless the tree
  publishes one whole 128 KiB frame per CPU (`GICR_SIZE`), not the region the
  firmware happens to reserve.
* **Unbacked PL061 window** — the panic that followed was a *synchronous
  external abort* on the button controller's `GPIOIEV`/`GPIOIE`, and the fix is
  to not publish a node for a window the machine cannot back.

Bring-up now runs the **whole IOKit matching phase**: 1122 personalities are
sent, every kext in the collection loads and starts (`AppleARMGIC`,
`IOGraphicsFamily` is load tag 66, …), BSD init comes up (MAC Framework, AMFI
developer mode) and the remaining kexts load through load tag 92 (apfs, nfs,
tmpfs, ppp, l2tp) with NVRAM writes syncing. It then stops waiting for a root
device:

```
Waiting on <dict ID="0"><key>IOProviderClass</key><string ID="1">IOMedia</string>…
```

Getting there took one diagnosis. The boot used to panic just after AMFI with

```
panic(cpu 0 caller 0xfffffe000a0899e8): Undefined kernel instruction:
  pc=0xfffffe000a828b24 instr=d53ef008 @sleh.c:1930
```

`d53ef008` is `mrs x8, S3_6_C15_C0_0`: the **default implementation-specific
error handler** `arm64_implementation_specific_error` reads a bank of Apple
IMPDEF syndrome registers (`S3_6_C15_C0_0`, `S3_3_C15_{C0,C8,C9,C10}_0`,
`S3_4_C15_C0_0`). An Apple CPU implements those encodings; QEMU's `-cpu max`
leaves them unallocated, so the read takes "unknown reason" and `sleh` panics.
That reader is only the *fallback* of a dispatcher `sleh_synchronous`
tail-calls for the trapped / implementation-defined exception classes: it first
offers the exception to a global handler object and a per-thread handler, and
neither is registered this early in the boot.

The **root cause** is the exception it was trying to report. The first
exception on the boot is a data abort — `ESR_EL1 = 0x96000050`, EC `0x25`,
DFSC `0x10`, i.e. a synchronous external abort — from
`AppleVirtualPlatform` at `pc 0xfffffe0008a92bd4`:

```
ldr  x8, [x19, #208]        ; the driver's mapped GPIO window
mov  w9, #0x40
strb w9, [x8, #1036]        ; GPIOIEV, offset 0x40c
strb w9, [x8, #1040]        ; GPIOIE,  offset 0x410
```

That is the AVP's GPIO driver enabling the interrupt for line 6, and the window
it writes to is a hole. QEMU's *generated* device tree advertises
`pl061@9030000` with a `gpio-keys` child, but the machine never instantiates the
controller — it is not a user-creatable device (`-device pl061` is rejected),
and `info mtree` shows nothing between `pl031@0x09010000` and
`acpi-ged@0x09080000`. Publishing the node tells a driver to map an address that
no device backs, and its first register write aborts in the kernel.

So the fix is a **machine-description** one: a node whose device no machine can
back is worse than no node, and `build_adt.py` plus Trestle's QEMU machine
(`g_qemu_windows`) leave it out the way they already leave out `avp-rtc`,
`avp-ctrr`, `avp-sealed-registers` and `pvpanic`. Trestle's AVP description
still carries the window (`0x10060000`, GIC id `0x25`) because the real platform
has the controller, and the machine description is the only thing that differs
between the two trees.

The root volume itself is `043-70867-635.dmg.aea` in the IPSW. It is an AEA
(profile 1) archive, but it is **not** device-bound: its auth data names a
public PEM and an HPKE-wrapped key, so `tools/aea_decrypt.py` decrypts it while
Range-fetching it from Apple's CDN, producing a raw APFS container
(`NXSB`, 13.21 GiB) — the raw block device macOS wants. See
[`docs/ipsw.md`](ipsw.md).

Next is that root device. The decrypted volume is a raw APFS container
(`NXSB`, 13.21 GiB) and can be handed to the guest as a block device, but XNU
binds it through the platform's storage path: the AVP presents its virtio
devices behind the `pcie` node (`pcie,vmappl1`, `#address-cells` = 3, a 28-byte
`ranges`, `msi-frame-index` = 2, `interrupt-base` = 0x40), and that programming
model has to be understood before any disk can be attached. The remaining
platform devices (timers, GIC routing, the sealed-register and CTRR windows) are
likewise virtio/AAPL devices that Trestle is meant to emulate.
