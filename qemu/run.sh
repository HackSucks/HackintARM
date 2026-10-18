#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

#
# qemu/run.sh - boot Gatehouse + XNU on QEMU `virt` with AAVMF (EDK2).
#
# Builds the ESP tree (build/esp) from gatehouse/ and kernel/, then launches
# QEMU with the TCG (software) CPU so this works on an x86_64 host.  A GDB
# stub is available on :1234 (GDB=1) so LLDB/GDB can attach without stopping
# the boot; it is opt-in because runs with it have been seen to stall under
# TCG.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GH="$ROOT/gatehouse"
# The kernel image.  This must be the *kernel collection* (MH_FILESET): XNU's
# kext loading, IOKit matching and the whole boot path below depend on the
# collection layout.  A bare kernel (e.g. kernel.development.vmapple, the
# kernel slice on its own) parses but panics early in
# IOPlatformExpertDevice::generatePlatformUUID, so it is never the right image
# to bring up with.  Override with KERNEL=/path/to/other.kc when needed.
KERNEL="${KERNEL:-$ROOT/kernel/kernelcache.release.vma2.kc}"
ESP="$ROOT/build/esp"
MEM="${MEM:-3G}"
CPU="${CPU:-max}"
GDB_PORT="${GDB_PORT:-1234}"
# The GDB stub is opt-in.  Runs launched with it (GDB=1) have repeatedly been
# observed to park the vCPU thread under TCG -- guest PC somewhere in early
# boot, thread in state S, utime/stime frozen for minutes, so the boot only
# appears to hang -- while identical runs without it boot straight through.
# Nothing needs the stub unless a debugger is actually going to attach, so the
# default is off.  Use GDB=1 GDB_PORT=1234 ... when you want to connect.
USE_GDB="${GDB:-0}"
EXTRA=("$@")

# The root volume, as a raw block device.  XNU's storage stack is
# AppleVirtIOStorageDevice behind AppleVirtIOTransport, whose PCI transport
# matches the *generic* virtio ids (AppleVirtIOBlock carries
# IOVirtIOPrimaryMatch = 0x00021af4 = virtio type 2, vendor 0x1af4), so a
# plain virtio-blk-pci is the right device; what was missing was the guest
# enumerating the bus at all, which is what /arm-io/pcie is for.  The image is
# opened read-only by default: it is the only decrypted copy of the volume, and
# a boot that writes to it would have to be redone from the IPSW.
ROOTIMG="${ROOTIMG:-/mnt/windows2/vmapple-rootfs/043-70867-635.dmg}"
ROOTIMG_RO="${ROOTIMG_RO:-1}"

FW_CODE=/usr/share/edk2/aarch64/QEMU_EFI.fd
FW_VARS=/usr/share/edk2/aarch64/QEMU_VARS.fd

echo "== building gatehouse =="
make -C "$GH" ${STALL:+STALL=$STALL} >/dev/null

if [[ ! -f "$KERNEL" ]]; then
  echo "error: kernel image not found: $KERNEL" >&2
  echo "       (extract one from an IPSW; see README.local.md)" >&2
  exit 1
fi

echo "== building device tree =="
python3 "$GH/dt/build_adt.py" -o "$ROOT/build/gatehouse.adt"

echo "== staging ESP =="
rm -rf "$ESP"
mkdir -p "$ESP/EFI/BOOT" "$ESP/gatehouse"
cp "$GH/BOOTAA64.EFI" "$ESP/EFI/BOOT/BOOTAA64.EFI"
cp "$KERNEL" "$ESP/gatehouse/kernel"
cp "$ROOT/build/gatehouse.adt" "$ESP/gatehouse/gatehouse.adt"
ls -l "$ESP/EFI/BOOT/BOOTAA64.EFI" "$ESP/gatehouse/"

# XNU's pe_fiq.c is a GICv3 driver: pe_init_fiq() maps /arm-io/gic's GICD and
# walks the GICR redistributor frames.  QEMU's virt machine defaults to GICv2
# under TCG, which has no redistributors at all (the read of GICR_TYPER lands
# in an unmapped hole and takes a synchronous external abort), so pin GICv3.
QARGS=(
  # highmem-ecam=off puts the ECAM at 0x3f000000 (16 MB, 16 buses) instead of
  # 0x4010000000.  That keeps the host bridge's "reg" inside /arm-io's SoC
  # window, which is what lets the guest resolve the node to IODeviceMemory at
  # all; it also matches the reference platform, whose ECAM is low
  # (0x40000000).  See PCIE_ECAM_PHYS in gatehouse/dt/build_adt.py.
  #
  # highmem=off removes QEMU's 64-bit PCI MMIO aperture (0x8000000000..).
  # Without it, UEFI allocates the modern virtio BAR (BAR4: 64-bit
  # prefetchable, 16 KB, and the only place a modern-only virtio device puts
  # its common/notify/device config) up in that aperture, where nothing in the
  # guest's tree describes it: the AVP's /arm-io/pcie carries a single 32-bit
  # "ranges" entry because Apple's own PCIe devices are 32-bit only.  XNU then
  # has no IODeviceMemory for the virtio transport, the transport never brings
  # up AppleVirtIOBlock, no IOMedia appears and the kernel sits in the boot
  # picker waiting for a root.  With the aperture gone, UEFI falls back to
  # placing 64-bit BARs inside the 32-bit window (0x10000000..0x13ff0000),
  # which our "ranges" already describes.  The price is the RAM above 4G:
  # highmem=off leaves 3G at 0x40000000..0x100000000, and MEM + the
  # dram-base/dram-size in gatehouse/dt/build_adt.py (and trestle's QEMU
  # machine description) have to agree on that.
  -M virt,gic-version=3,highmem-ecam=off,highmem=off
  -cpu "$CPU"
  -m "$MEM"
  -bios "$FW_CODE"
  -nographic
  -drive "if=none,id=hd0,format=raw,file=fat:rw:$ESP"
  # The AVP describes no I/O port window (its "ranges" carries only MMIO), and
  # QEMU's own vmapple machine force-disables legacy virtio for the same
  # reason (vmapple_compat_defaults sets virtio-pci.disable-legacy=on).  A
  # modern-only device has no I/O BAR to place.  It has to be set per device:
  # a -global would also hit the non-transitional variants, which do not carry
  # the property.
  -device virtio-blk-pci,drive=hd0,disable-legacy=on
)

if [[ -n "$ROOTIMG" && -f "$ROOTIMG" ]]; then
  echo "== attaching root volume: $ROOTIMG (ro=$ROOTIMG_RO) =="
  if [[ "$ROOTIMG_RO" == "1" ]]; then
    QARGS+=(-drive "if=none,id=rootvol,format=raw,readonly=on,file=$ROOTIMG")
  else
    QARGS+=(-drive "if=none,id=rootvol,format=raw,file=$ROOTIMG")
  fi
  QARGS+=(-device "virtio-blk-pci,drive=rootvol,disable-legacy=on")
elif [[ -n "$ROOTIMG" ]]; then
  echo "== root volume $ROOTIMG not present; booting without a root disk =="
fi

if [[ "$USE_GDB" == "1" ]]; then
  QARGS+=(-gdb "tcp::$GDB_PORT")
fi

echo "== launching QEMU (gdb=$USE_GDB port=$GDB_PORT) =="
exec qemu-system-aarch64 "${QARGS[@]}" "${EXTRA[@]}"
