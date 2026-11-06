// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// CheckNodeLayouts is checkNodeLayouts for the external tests.
var CheckNodeLayouts = checkNodeLayouts

// checkNodeLayouts finds every B-tree node in a 4096-byte-block image and
// checks that its space adds up: the table of contents indexes every record,
// each key lies in the key area and each value in the value area, and header,
// table of contents, keys, free space, values and footer fill exactly one
// block. It returns how many nodes it checked.
//
// It exists because a node that overflows its block is otherwise silent: the
// writer's own reader follows the table of contents and never notices that the
// free-space length has wrapped, but fsck_apfs rejects the tree. Two such
// overflows shipped before this check existed (a file-system tree index of long
// names, and an extentref root-leaf of 111 or 112 records).
func checkNodeLayouts(img []byte) (int, error) {
	const bs = 4096
	checked := 0
	for off := 0; off+bs <= len(img); off += bs {
		blk := img[off : off+bs]
		typ := binary.LittleEndian.Uint32(blk[objOffType:]) & 0xffff
		if typ != objectTypeBtree && typ != objectTypeBtreeNode {
			continue
		}
		if !apfs.ValidateChecksum(blk) {
			continue
		}
		if err := checkNodeLayout(blk); err != nil {
			return checked, fmt.Errorf("node at block %d: %w", off/bs, err)
		}
		checked++
	}
	return checked, nil
}

func checkNodeLayout(blk []byte) error {
	bs := len(blk)
	le := binary.LittleEndian
	flags := le.Uint16(blk[btnOffFlags:])
	nkeys := int(le.Uint32(blk[btnOffNkeys:]))
	tableOff, tableLen := int(le.Uint16(blk[btnOffTableSpace:])), int(le.Uint16(blk[btnOffTableSpace+2:]))
	freeOff, freeLen := int(le.Uint16(blk[btnOffFreeSpace:])), int(le.Uint16(blk[btnOffFreeSpace+2:]))

	footer := 0
	if flags&btnodeRoot != 0 {
		footer = sizeofBtreeInfo
	}
	fixed := flags&btnodeFixedKVSize != 0
	entrySize := sizeofKvloc
	keySize, valSize := 0, 0
	if fixed {
		entrySize = sizeofKvoff
		switch subtype := le.Uint32(blk[objOffSubtype:]); subtype {
		case objectTypeOmap:
			keySize, valSize = sizeofOmapKey, sizeofOmapVal
		case objectTypeOmapSnapshot:
			keySize, valSize = 8, sizeofOmapSnapshot
		case objectTypeSpacemanFreeQueue:
			keySize, valSize = sizeofSpacemanFreeQueueKey, 8
		default:
			return fmt.Errorf("fixed-size node of unknown subtype %#x", subtype)
		}
		if flags&btnodeLeaf == 0 {
			valSize = childPtrSize
		}
	}

	if tableOff != 0 {
		return fmt.Errorf("table of contents at offset %d, want 0", tableOff)
	}
	if nkeys*entrySize > tableLen {
		return fmt.Errorf("%d records need a %d-byte table of contents, have %d", nkeys, nkeys*entrySize, tableLen)
	}
	keyStart := sizeofBtreeNodePhys + tableLen
	freeStart := keyStart + freeOff
	freeEnd := freeStart + freeLen
	valEnd := bs - footer
	if freeEnd > valEnd {
		return fmt.Errorf("free space ends at %d, past the value area's end at %d", freeEnd, valEnd)
	}

	valUsed := 0
	for i := range nkeys {
		toc := sizeofBtreeNodePhys + i*entrySize
		var k, kl, v, vl int
		if fixed {
			k, kl = int(le.Uint16(blk[toc:])), keySize
			v, vl = int(le.Uint16(blk[toc+2:])), valSize
		} else {
			k, kl = int(le.Uint16(blk[toc:])), int(le.Uint16(blk[toc+2:]))
			v, vl = int(le.Uint16(blk[toc+4:])), int(le.Uint16(blk[toc+6:]))
		}
		if k+kl > freeOff {
			return fmt.Errorf("record %d: key [%d,%d) runs past the key area's %d bytes", i, k, k+kl, freeOff)
		}
		if v < vl || valEnd-v < freeEnd {
			return fmt.Errorf("record %d: value at %d back from %d overlaps the free space", i, v, valEnd)
		}
		valUsed = max(valUsed, v)
	}
	if freeEnd+valUsed != valEnd {
		return fmt.Errorf("header %d + toc %d + keys %d + free %d + values %d + footer %d = %d, want %d",
			sizeofBtreeNodePhys, tableLen, freeOff, freeLen, valUsed, footer,
			freeEnd+valUsed+footer, bs)
	}
	return nil
}
