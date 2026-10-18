# HackintARM

Reviving Hackintosh on ARM64 laptops, now that macOS 27+ is Apple Silicon only.

---

## Status

**Late-stage boot.** The full release, retail kernelcache is booting and the
root volume mounts.

The blocker is now post-mount: the kernel goes idle in `wfi` after the root
volume is mounted, waiting on something that never arrives.

Reaching the root volume needed one kernel-collection workaround (see
`tools/kc_patch.py`). macOS 27's `IOPCIDevice::extendedFindPCICapability()`
answers vendor-capability lookups out of a per-device capability dictionary
built by `IOPCIBridge::constructCapabilitiesDict()`. A virtio-pci device
exposes five capabilities that all share capability ID `0x09`, so that
dictionary collapses to a single entry and the fast path hands back the same
capability for every offset. `AppleVirtIOPCITransport::start()` walks vendor
capabilities with `extendedFindPCICapability(9, &offset)` until it reports none
left — which never happens — so it spun forever and no root media appeared.
`tools/kc_patch.py` forces the reference config-space search; `qemu/run.sh`
applies it to the staged kernel copy, leaving `kernel/` pristine.

### Milestones
- [x] UART/serial reached
- [x] Kernelcache boots with all 236 kexts loaded
- [x] Past `AppleImage4`'s `mpo_policy_init`
- [x] Full KC booting into late-stage boot
- [x] Root transport starts, root media appears and the APFS volume mounts
- [ ] Userland

---

## Sub-projects

HackintARM is an umbrella project made up of the following parts, all bridge themed:

| Sub-project | What it is |
|---|---|
| **Gatehouse** | The EFI application/bootloader. It runs on anything with UEFI, so no bare-metal bring-up is needed. Its core work is done, and the focus has moved to Trestle. |
| **Trestle** | A hypervisor that provides what VMApple's hypervisor did, but also doubles as a layer that **spoofs the real hardware** VMApple expects. It can also supply drivers where needed, ported from BSD or Linux source. |
| **Lantern** *(upcoming)* | Handles translation from Paravirtual GPU device to the real hardware. |

---

## Tooling

HackintARM will ship with all the tooling needed to:

1. Fetch an **exact copy** of the kernelcache (KC) and the **AEA-encrypted root image** I use.
2. **Decrypt** that AEA image.

That way anyone can reproduce the exact setup without guessing at versions.

---

## Target

macOS 27, using the **VMApple kernelcache**, since it makes far fewer platform assumptions than the bare-metal M-series ones.

---

## Requirements

- An ARMv8.2/8.3+ SoC with **pointer authentication (pauth)**. SoCs without it are incompatible with HackintARM for now.
- Support for **16K pages/4K page based processor that can HANDLE 16K pages.**.
- UEFI firmware (for Gatehouse).

---

# ETA?
ETA to booting till late-stage is now.. done.
ETA to fully working? could be many weeks.
