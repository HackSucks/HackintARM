#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors
#
# grab_vmapple_rootfs.sh -- pull the VirtualMac2,1 (vma2macosap) root volume
# out of the macOS 27 restore image, plus the plain images beside it.
#
# The root volume in the IPSW ("OS" in the BuildManifest) is shipped only as an
# Apple Encrypted Archive, 043-70867-635.dmg.aea.  It is not device-bound: the
# key is delivered HPKE-wrapped via Apple's public FCS key service and named in
# the archive's auth data, so tools/aea_decrypt.py decrypts it in place while
# Range-fetching the archive from Apple's CDN -- the encrypted copy is never
# stored.  The plaintext is a raw APFS container (NXSB), i.e. exactly the kind
# of raw block-device image macOS can be pointed at.
#
# The other root-ish members are encrypted too (Cryptex1,SystemOS, BaseSystem),
# or plain but not the root (RestoreRamDisk, the cryptexes).  They are grabbed
# here for reference; the cryptexes can be decrypted the same way.
#
# Decryption needs a Python with `cryptography` and `lzfse`:
#     python3 -m venv .venv && .venv/bin/pip install cryptography lzfse
# then point PYTHON at it.
#
# Usage: grab_vmapple_rootfs.sh [DEST]      (default /mnt/windows2/vmapple-rootfs)
set -uo pipefail

URL="https://updates.cdn-apple.com/2026FallFCS/afcfc88e-bbe6-44bf-a5da-07c56eebc06c/UniversalMac_27.0_26A428_Restore.ipsw"
DEST="${1:-/mnt/windows2/vmapple-rootfs}"
PYTHON="${PYTHON:-python3}"
HERE="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$DEST"

# root volume: fetched from the CDN and decrypted straight to a raw APFS image
echo "### root volume (decrypt 043-70867-635.dmg.aea -> 043-70867-635.dmg)"
"$PYTHON" "$HERE/aea_decrypt.py" --url "$URL" --member 043-70867-635.dmg.aea --fcs \
    --out "$DEST/043-70867-635.dmg"

# plain images (stored/deflated members, straight copy)
PLAIN=(
    094-86031-269.dmg         # Cryptex1,RosettaOS (raw APFS)
    043-70637-685.dmg         # Cryptex1,AppOS (raw APFS)
    043-70833-682.dmg         # RestoreRamDisk (IM4P inside)
    043-70842-681.dmg         # IM4P
)
for m in "${PLAIN[@]}"; do
    echo "### $m"
    for attempt in $(seq 1 100); do
        if "$PYTHON" "$HERE/ipsw_extract.py" --url "$URL" --extract "$m" --out "$DEST/$m"; then
            break
        fi
        echo "### retry $m (attempt $attempt)" >&2
        sleep 5
    done
done

# encrypted cryptexes (optional): same decryption path as the root
if [[ "${CRYPTEXES:-0}" == "1" ]]; then
    for m in 043-70701-646.dmg.aea 043-70822-678.dmg.aea 022-20292-673.dmg.aea; do
        echo "### $m"
        "$PYTHON" "$HERE/aea_decrypt.py" --url "$URL" --member "$m" --fcs \
            --out "$DEST/${m%.aea}"
    done
fi
echo "### done"
