#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors
#
# grab_vmapple_rootfs.sh -- pull the VirtualMac2,1 (vma2macosap) root-volume
# images out of the macOS 27 restore image with ipsw_extract.py.
#
# The IPSW is ~25 GiB and most of it is irrelevant here, so we Range-fetch only
# the members we care about:
#
#   043-70867-635.dmg.aea   the root volume ("OS" in the BuildManifest);
#                           11.3 GiB, Apple Encrypted Archive (AEA), keyed via
#                           com.apple.wkms.url -> Apple's WKMS.  Grabbed as-is;
#                           decrypting it needs the restore key from Apple.
#   094-86031-269.dmg       Cryptex1,RosettaOS: plain raw APFS image (NXSB)
#   043-70637-685.dmg       Cryptex1,AppOS: plain raw APFS image
#   043-70833-682.dmg       RestoreRamDisk: IM4P-wrapped payload
#   043-70842-681.dmg       IM4P-wrapped payload
#
# Everything is streamed to disk in chunks and, since these are stored members,
# a partial file is resumed on a re-run; a dropped connection costs only the
# bytes in flight.
#
# Usage: grab_vmapple_rootfs.sh [DEST]      (default /mnt/windows2/vmapple-rootfs)
set -uo pipefail

URL="https://updates.cdn-apple.com/2026FallFCS/afcfc88e-bbe6-44bf-a5da-07c56eebc06c/UniversalMac_27.0_26A428_Restore.ipsw"
DEST="${1:-/mnt/windows2/vmapple-rootfs}"
HERE="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$DEST"

MEMBERS=(
    043-70867-635.dmg.aea     # root volume (AEA)
    094-86031-269.dmg         # Cryptex1,RosettaOS (APFS)
    043-70637-685.dmg         # Cryptex1,AppOS (APFS)
    043-70833-682.dmg         # RestoreRamDisk (IM4P)
    043-70842-681.dmg         # IM4P
)

for m in "${MEMBERS[@]}"; do
    out="$DEST/$m"
    echo "### $m"
    for attempt in $(seq 1 100); do
        if python3 "$HERE/ipsw_extract.py" --url "$URL" --extract "$m" --out "$out"; then
            break
        fi
        echo "### retry $m (attempt $attempt)" >&2
        sleep 5
    done
done
echo "### done"
