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
# The machine being described is an Apple T8103 (M1) class SoC: it has
# pointer authentication, but no SVE and no SME.  QEMU's `max` advertises
# both, which makes XNU probe the SME control registers (SMCR_EL1/SMPRI_EL1)
# and take an EL2 trap for hardware the real target does not have -- and, if
# it were enabled instead, tempt XNU into streaming-mode code paths that
# cannot work on the target.  Match the target here rather than teaching the
# guest about features it will never see.
#
# pauth-impdef=on: QEMU's `max` implements the PAC instructions with a real
# keyed hash -- many host instructions per guest instruction -- which is a
# large part of why a TCG boot of arm64e userland is slow.  IMPDEF uses the
# architecture's cheap, implementation-defined algorithm instead.  This is
# sound here because XNU and every process only ever sign and authenticate
# their own pointers, all under keys they set themselves: any consistent
# implementation gives the same accept/reject answers.  It is a bring-up speed
# knob only -- real hardware runs the native instructions, so this is not
# something the target needs or the ADT describes.
CPU="${CPU:-max,sve=off,sme=off,pauth-impdef=on}"
# Guest CPUs.  One by default: guest secondary bring-up runs through the
# platform PMGR/PSCI path, which is not complete yet, so publishing more CPUs
# than the machine can actually start would only stall the boot.  When that
# path lands, one number drives both QEMU's -smp and the tree's /cpus count
# (build_adt.py --cpus), which is also what Gatehouse reads back for cpus=N.
# The T8103 target has MAX_CPUS 8, so 8 is the natural upper bound.
CPUS="${CPUS:-1}"
# Translation cache, in MiB.  XNU's boot touches a lot of distinct code and the
# stock 32 MiB TB fills and flushes repeatedly under TCG; a larger one trades
# host RAM for far fewer translation flushes.  Guest RAM (MEM, 3G by default)
# plus this has to fit, so lower it if the host is tight.
TB_SIZE="${TB_SIZE:-1024}"
GDB_PORT="${GDB_PORT:-1234}"
# The GDB stub is opt-in.  Runs launched with it (GDB=1) have repeatedly been
# observed to park the vCPU thread under TCG -- guest PC somewhere in early
# boot, thread in state S, utime/stime frozen for minutes, so the boot only
# appears to hang -- while identical runs without it boot straight through.
# Nothing needs the stub unless a debugger is actually going to attach, so the
# default is off.  Use GDB=1 GDB_PORT=1234 ... when you want to connect.
USE_GDB="${GDB:-0}"
EXTRA=("$@")

# Root disk.  The assembled GPT image has the iSC and APFS partitions, with
# System, Data and Preboot volumes in the APFS container.  Prefer its qcow2
# overlay when present: the guest needs Preboot and Data writable, while the
# base `.img` remains untouched.  The standalone decrypted `.dmg` is only a
# fallback; it does not contain the full boot disk layout.
if [[ -f /mnt/windows2/combined2.qcow2 ]]; then
  ROOTIMG_DEFAULT=/mnt/windows2/combined2.qcow2
  ROOTFMT_DEFAULT=qcow2
  ROOTIMG_RO_DEFAULT=0
else
  ROOTIMG_DEFAULT=/mnt/windows2/vmapple-rootfs/043-70867-635.dmg
  ROOTFMT_DEFAULT=raw
  ROOTIMG_RO_DEFAULT=1
fi
ROOTIMG="${ROOTIMG:-$ROOTIMG_DEFAULT}"
ROOTIMG_RO="${ROOTIMG_RO:-$ROOTIMG_RO_DEFAULT}"
ROOTFMT="${ROOTFMT:-$ROOTFMT_DEFAULT}"

# Auxiliary storage (the iSC container).  macOS 27's mount-phase-1 mounts
# xART off a GPT partition whose type GUID is 69646961-6700-11AA-AA11-00306543ECAC
# ("Content Hint" in IOKit terms) and treats its absence as fatal.  The image
# built by tools/mkisc carries that partition and the iSCPreboot/xART/Hardware
# volumes; a real Mac has the same partition on the same disk as the root
# container.  Unset by default so an ordinary boot is unchanged.
ISCIMG="${ISCIMG:-}"
ISCFMT="${ISCFMT:-raw}"

# The root volume's static trust cache (IMG4 "trst" member).  XNU needs it to
# accept the platform binaries on that volume -- launchd first of all -- and
# Gatehouse delivers it the way iBoot does: it loads the payload, puts it in
# the boot-data window and publishes /chosen/memory-map/TrustCache.  Override
# with TRUSTCACHE=/path/to/file.
TRUSTCACHE="${TRUSTCACHE:-$ROOT/kernel/trustcache.release.vma2}"

# The restore ramdisk (IMG4 "rdsk" member, e.g. 043-70833-682.dmg from the
# IPSW).  When RAMDISK is set, Gatehouse hands it to XNU the way iBoot does for
# a restore boot: the payload goes inside the boot window, /chosen/memory-map
# gets a RAMDisk entry, and the command line names it as the root device
# (rd=md0).  Its own trust cache has to travel with it -- the ramdisk binaries
# are not in the platform cache -- and Gatehouse puts that one first, because
# only the first module becomes the static trust cache.  Unset by default, so
# an ordinary boot is unaffected.
RAMDISK="${RAMDISK:-}"
RAMDISKTC="${RAMDISKTC:-$ROOT/kernel/ramdisk.trustcache}"

FW_CODE=/usr/share/edk2/aarch64/QEMU_EFI.fd
FW_VARS=/usr/share/edk2/aarch64/QEMU_VARS.fd

echo "== building gatehouse =="
make -C "$GH" clean >/dev/null
if [[ "${LANTERN:-0}" == "1" ]]; then
  make -C "$GH" ${STALL:+STALL=$STALL} LANTERN=1 >/dev/null
else
  make -C "$GH" ${STALL:+STALL=$STALL} >/dev/null
fi

if [[ ! -f "$KERNEL" ]]; then
  echo "error: kernel image not found: $KERNEL" >&2
  echo "       (extract one from an IPSW; see docs/bringup.md)" >&2
  exit 1
fi

echo "== building device tree =="
LANTERN_ARG=""
if [[ "${LANTERN:-0}" == "1" ]]; then
  # LANTERN_GSRP selects the gpu-sysmem-reserve-percent form the gfx node
  # carries: syscfg (authentic unresolved string, default), omit, or a number.
  LANTERN_ARG="--lantern --gsrp ${LANTERN_GSRP:-syscfg}"
fi
python3 "$GH/dt/build_adt.py" -o "$ROOT/build/gatehouse.adt" --cpus "$CPUS" $LANTERN_ARG

echo "== staging ESP =="
rm -rf "$ESP"
mkdir -p "$ESP/EFI/BOOT" "$ESP/gatehouse"
cp "$GH/BOOTAA64.EFI" "$ESP/EFI/BOOT/BOOTAA64.EFI"
cp "$KERNEL" "$ESP/gatehouse/kernel"
cp "$ROOT/build/gatehouse.adt" "$ESP/gatehouse/gatehouse.adt"
if [[ -f "$TRUSTCACHE" ]]; then
  cp "$TRUSTCACHE" "$ESP/gatehouse/trustcache"
else
  echo "== no trust cache at $TRUSTCACHE: platform binaries will be rejected =="
fi
# Bring-up handover (see gatehouse/src/patch.c): the program to run as PID 1,
# installed only when INIT is set.  Nothing to revert afterwards -- an ordinary
# boot has no such file and runs launchd.
if [[ -n "${INIT:-}" ]]; then
  printf '%s\n' "$INIT" > "$ESP/gatehouse/init"
  echo "== PID 1 override: $INIT =="
fi
# ... and the one argument it gets, when it needs one.  "sh /dev/console" is
# the rescue shell: PID 1 starts with no descriptors, so the shell has to open
# the console itself.  Only meaningful alongside INIT.
if [[ -n "${INITARG:-}" ]]; then
  printf '%s\n' "$INITARG" > "$ESP/gatehouse/initarg"
  echo "== PID 1 argument: $INITARG =="
fi
# Extra kernel boot arguments for a diagnostic run, one line.  Absent by
# default, so an ordinary boot keeps Gatehouse's built-in command line.
if [[ -n "${BOOTARGS:-}" ]]; then
  printf '%s\n' "$BOOTARGS" > "$ESP/gatehouse/bootargs"
  echo "== extra boot args: $BOOTARGS =="
fi
# Restore ramdisk handover: the IMG4 object as downloaded (Gatehouse unwraps the
# "rdsk" payload) plus the trust cache generated for its contents.
if [[ -n "$RAMDISK" ]]; then
  if [[ -f "$RAMDISK" ]]; then
    cp "$RAMDISK" "$ESP/gatehouse/ramdisk"
    echo "== restore ramdisk: $RAMDISK =="
    if [[ -f "$RAMDISKTC" ]]; then
      cp "$RAMDISKTC" "$ESP/gatehouse/ramdisktc"
      echo "== ramdisk trust cache: $RAMDISKTC =="
    else
      echo "== no ramdisk trust cache at $RAMDISKTC: its binaries will be rejected =="
    fi
  else
    echo "error: ramdisk not found: $RAMDISK" >&2
    exit 1
  fi
fi
ls -l "$ESP/EFI/BOOT/BOOTAA64.EFI" "$ESP/gatehouse/"

# QEMU's directory-backed FAT drive creates its scratch image in /var/tmp,
# which is read-only in some managed runners. Build an ordinary FAT image in
# the workspace instead; Gatehouse only reads this ESP during boot.
ESPIMG="$ROOT/build/esp.img"
truncate -s 128M "$ESPIMG"
mkfs.vfat -F 32 "$ESPIMG" >/dev/null
mcopy -s -i "$ESPIMG" "$ESP/EFI" ::/EFI
mcopy -s -i "$ESPIMG" "$ESP/gatehouse" ::/gatehouse

# The machine's RAM.  Gatehouse discovers the real window from the firmware
# memory map, so MEM is the only place a capacity is chosen and every value
# here follows it.  The host adapter learns the window from the mailbox in
# the guest's RAM, not from a hardcoded base.
MACHINE="virt,gic-version=3,highmem-ecam=off,highmem=off"
LANTERN_ARGS=()
RAMFILE=""
HOSTPID=""
if [[ "${LANTERN:-0}" == "1" ]]; then
  # The RAM file has to be on a filesystem that supports a writable MAP_SHARED
  # mapping; NTFS/FUSE (this workspace's /mnt/newvol) refuses one, so the
  # default is tmpfs.  Point LANTERN_RAMFILE at a real disk to keep a capture.
  RAMFILE="${LANTERN_RAMFILE:-${TMPDIR:-/tmp}/lantern-ram-$$.bin}"
  rm -f "$RAMFILE"
  truncate -s "$MEM" "$RAMFILE"

  MACHINE_EXTRA="${VIRT_EXTRA:-}"
  if [[ ",$MACHINE_EXTRA," != *",virtualization=on,"* ]]; then
    MACHINE_EXTRA="${MACHINE_EXTRA:+$MACHINE_EXTRA,}virtualization=on"
  fi
  MACHINE="$MACHINE,memory-backend=lantern_ram,$MACHINE_EXTRA"
  LANTERN_ARGS=(-object "memory-backend-file,id=lantern_ram,size=$MEM,mem-path=$RAMFILE,share=on")

  # The dist must be built for an ARM64 guest's 16 KiB pages even though it
  # runs on this x86-64 host; see patches/reims-vgpu-arm64-guest-page-size.patch.
  : "${REIMS_VGPU_PKG_CONFIG_PATH:=$ROOT/build/reims-dist-2/lib/pkgconfig}"
  : "${PKG_CONFIG_PATH:=${REIMS_VGPU_PKG_CONFIG_PATH}}"
  export PKG_CONFIG_PATH
  make -C "$ROOT/lantern/host" >/dev/null
  libdir="$(pkg-config --variable=libdir reims-vgpu)"
  export LD_LIBRARY_PATH="$libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

  # The adapter takes the RAM file and finds the mailbox and its geometry by
  # magic.  LANTERN_RAM_BASE is only a cross-check for a hand-run host.
  LANTERN_HOST_ARGS=("$RAMFILE")
  if [[ -n "${LANTERN_RAM_BASE:-}" ]]; then
    LANTERN_HOST_ARGS+=("$LANTERN_RAM_BASE")
  fi
  "$ROOT/lantern/host/lantern-host" "${LANTERN_HOST_ARGS[@]}" &
  HOSTPID=$!
  trap 'kill "$HOSTPID" 2>/dev/null || true; wait "$HOSTPID" 2>/dev/null || true; rm -f "$RAMFILE"' EXIT
fi

# XNU's pe_fiq.c is a GICv3 driver: pe_init_fiq() maps /arm-io/gic's GICD and
# walks the GICR redistributor frames.  QEMU's virt machine defaults to GICv2
# under TCG, which has no redistributors at all (the read of GICR_TYPER lands
# in an unmapped hole and takes a synchronous external abort), so pin GICv3.
QARGS=(
  # TCG tuning.  thread=multi is the modern default for aarch64-on-x86 and
  # costs nothing at CPUS=1; tb-size overrides the stock 32 MiB translation
  # cache.  Both only take effect under the TCG accelerator (there is no KVM
  # for an aarch64 guest on this x86-64 host), and passing -accel explicitly
  # keeps a run from silently picking a different one.
  -accel "tcg,thread=multi,tb-size=$TB_SIZE"
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
  # highmem=off leaves 3G at 0x40000000..0x100000000 with the default MEM.
  # Gatehouse reads the firmware memory map on every boot and rewrites
  # /chosen dram-base and dram-size, /pram and the /arm-io window to match,
  # so MEM is the only place a capacity is chosen.
  -M "$MACHINE"
  -cpu "$CPU"
  -m "$MEM"
  # The vCPUs QEMU exposes must be at least the CPUs the tree publishes
  # (build_adt.py --cpus), or XNU would try to start a core that does not
  # exist; extras are harmless because they merely sit parked.
  -smp "$CPUS"
  -bios "$FW_CODE"
  -drive "if=none,id=hd0,format=raw,file=$ESPIMG"
  # The AVP describes no I/O port window (its "ranges" carries only MMIO), and
  # QEMU's own vmapple machine force-disables legacy virtio for the same
  # reason (vmapple_compat_defaults sets virtio-pci.disable-legacy=on).  A
  # modern-only device has no I/O BAR to place.  It has to be set per device:
  # a -global would also hit the non-transitional variants, which do not carry
  # the property.
  -device virtio-blk-pci,drive=hd0,disable-legacy=on
)

if [[ ${#LANTERN_ARGS[@]} -gt 0 ]]; then
  QARGS+=("${LANTERN_ARGS[@]}")
fi


if [[ -n "$ROOTIMG" && -f "$ROOTIMG" ]]; then
  echo "== attaching root volume: $ROOTIMG (ro=$ROOTIMG_RO fmt=$ROOTFMT) =="
  if [[ "$ROOTIMG_RO" == "1" ]]; then
    QARGS+=(-drive "if=none,id=rootvol,format=$ROOTFMT,readonly=on,file=$ROOTIMG")
  else
    QARGS+=(-drive "if=none,id=rootvol,format=$ROOTFMT,file=$ROOTIMG")
  fi
  QARGS+=(-device "virtio-blk-pci,drive=rootvol,disable-legacy=on")
elif [[ -n "$ROOTIMG" ]]; then
  echo "== root volume $ROOTIMG not present; booting without a root disk =="
fi

# iSC (auxiliary storage): a second virtio-blk is just a carrier here.  The
# guest finds the partition by its GPT type GUID, not by which disk it is on;
# folding it into the root disk's GPT is the faithful layout, and is what a
# machine that only passes one block device through needs.
if [[ -n "$ISCIMG" && -f "$ISCIMG" ]]; then
  echo "== attaching iSC volume: $ISCIMG (fmt=$ISCFMT) =="
  QARGS+=(-drive "if=none,id=iscdisk,format=$ISCFMT,file=$ISCIMG")
  QARGS+=(-device "virtio-blk-pci,drive=iscdisk,disable-legacy=on")
elif [[ -n "$ISCIMG" ]]; then
  echo "== iSC volume $ISCIMG not present; booting without auxiliary storage =="
fi

if [[ "$USE_GDB" == "1" ]]; then
  QARGS+=(-gdb "tcp::$GDB_PORT")
fi

# HMP monitor on a unix socket, opt-in.  Used to read guest kernel memory from
# the host (x/Ngx over HMP) while the guest is stuck, which is how the
# userland stalls so far were diagnosed.  wait=off so QEMU does not block
# waiting for a client before starting the machine.
if [[ -n "${MONITOR:-}" ]]; then
  rm -f "$MONITOR"
  QARGS+=(-monitor "unix:$MONITOR,server=on,wait=off")
fi

# Console.  By default the guest's serial port is QEMU's stdio, so a boot is
# run with its output redirected to a file and nothing can be typed into it.
# SERIAL=/path/to/socket puts the port on a unix socket instead and waits for a
# client before starting the guest, so an interactive boot -- a single-user
# shell, a recovery environment -- keeps every byte and can be driven with e.g.
#
#	socat -,raw,echo=0 UNIX-CONNECT:/tmp/opencode/ser.sock
#
# or build/console.py, which also tees the port to a log file.
if [[ -n "${SERIAL:-}" ]]; then
  # The pl011 carries XNU's own printf: pe_serial drives it from the
  # /arm-io/uart0 node ("arm,pl011"), which is where the boot log comes from.
  # Userland has no driver for "arm,pl011" at all, so it is a log and nothing
  # more.
  QARGS+=(-display none -serial "unix:$SERIAL,server=on,wait=on")
  # The guest's own console is a *virtio console*, exactly as on a
  # Virtualization.framework guest: com.apple.driver.AppleVirtIO's
  # AppleVirtIOConsole personality carries IOVirtIOPrimaryMatch = 0x00031af4
  # (virtio type 3, vendor 0x1af4) on IOProviderClass AppleVirtIOTransport, and
  # a modern-only virtio-serial-pci enumerates as exactly that.  It is the only
  # thing in the machine that turns into a tty, so it is the only place a
  # shell's stdin can come from.  A separate chardev rather than a mux of the
  # two: a mux routes input to one focused head only.  Nothing in the ADT has
  # to change -- AppleVirtIOPCITransport finds the device over PCI.
  if [[ -n "${CONSOLE:-}" ]]; then
    # No wait=on here: -chardev is created while the command line is parsed,
    # i.e. before -serial, so a blocking open would hold the whole machine
    # (including the pl011 that carries the boot log) hostage until a client
    # turned up.  Nothing writes to this port before userland, so there is
    # nothing to lose by opening it asynchronously.
    QARGS+=(-chardev "socket,id=vc0,path=$CONSOLE,server=on,wait=off"
            -device virtio-serial-pci,disable-legacy=on
            -device virtconsole,chardev=vc0)
  fi
else
  QARGS+=(-nographic)
fi

echo "== launching QEMU (gdb=$USE_GDB port=$GDB_PORT) =="
qemu-system-aarch64 "${QARGS[@]}" "${EXTRA[@]}"
