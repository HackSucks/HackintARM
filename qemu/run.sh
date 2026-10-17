#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

#
# qemu/run.sh - boot Gatehouse + XNU on QEMU `virt` with AAVMF (EDK2).
#
# Builds the ESP tree (build/esp) from gatehouse/ and kernel/, then launches
# QEMU with the TCG (software) CPU so this works on an x86_64 host.  A GDB
# stub is enabled on :1234 so LLDB/GDB can attach without stopping the boot.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GH="$ROOT/gatehouse"
KERNEL="${KERNEL:-$ROOT/kernel/kernel.development.vmapple}"
ESP="$ROOT/build/esp"
MEM="${MEM:-4G}"
CPU="${CPU:-max}"
GDB_PORT="${GDB_PORT:-1234}"
USE_GDB="${GDB:-1}"
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
  -M virt,gic-version=3,highmem-ecam=off
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
