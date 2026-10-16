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
  -M virt,gic-version=3
  -cpu "$CPU"
  -m "$MEM"
  -bios "$FW_CODE"
  -nographic
  -drive "if=none,id=hd0,format=raw,file=fat:rw:$ESP"
  -device virtio-blk-pci,drive=hd0
)

if [[ "$USE_GDB" == "1" ]]; then
  QARGS+=(-gdb "tcp::$GDB_PORT")
fi

echo "== launching QEMU (gdb=$USE_GDB port=$GDB_PORT) =="
exec qemu-system-aarch64 "${QARGS[@]}" "${EXTRA[@]}"
