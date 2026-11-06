// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"fmt"
)

// makeFSTree builds the volume's file-system tree. When every record fits in
// one node the tree is a single root-leaf at (paddr, oid); otherwise it grows
// as tall as it needs (see tree.go), its other nodes placed in the volume's
// file-system tree region. Every node is a virtual object mapped by the volume
// object map, and index records point at children by virtual oid, which the
// reader and fsck resolve through that map.
func (b volCtx) makeFSTree(paddr, oid uint64) error {
	recs := b.buildFSTreeRecords()

	longestKey, longestVal := 0, 0
	for _, r := range recs {
		if len(r.key) > longestKey {
			longestKey = len(r.key)
		}
		if len(r.val) > longestVal {
			longestVal = len(r.val)
		}
	}
	// The empty-volume special records set a floor for the longest key/value.
	if longestKey < sizeofDrecHashedKeyFixed+len("private-dir")+1 {
		longestKey = sizeofDrecHashedKeyFixed + len("private-dir") + 1
	}

	levels, err := varTreeLevels(recs, int(b.blocksize))
	if err != nil {
		return err
	}
	if n := uint64(treeNodeCount(levels) - 1); n != b.fsTreeNodes {
		return fmt.Errorf("apfswrite: file-system tree packed into %d non-root nodes, planned for %d", n, b.fsTreeNodes)
	}
	info := &fsTreeInfo{longestKey: longestKey, longestVal: longestVal, keyCount: len(recs)}
	return b.writeVarTree(levels, varTreeSpec{
		rootPaddr: paddr,
		rootOID:   oid,
		nodePaddr: func(j uint64) uint64 { return b.fsTreeNodeBase + j },
		nodeOID:   b.fsTreeNodeOID,
		childPtr:  b.fsTreeNodeOID,
		storage:   objVirtual,
		subtype:   objectTypeFSTree,
		footer: func(buf []byte, nodeCount int) {
			info.nodeCount = nodeCount
			b.setFSTreeInfo(buf, info)
		},
	})
}

// fsTreeInfo holds the values written into a file-system tree root node's btree_info.
type fsTreeInfo struct {
	longestKey int
	longestVal int
	keyCount   int
	nodeCount  int
}

// setFSTreeInfo writes a file-system tree root node's btree_info trailer.
func (b *builder) setFSTreeInfo(info []byte, f *fsTreeInfo) {
	binary.LittleEndian.PutUint32(info[0:], btreeKVNonaligned)     // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)           // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], uint32(f.longestKey)) // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], uint32(f.longestVal)) // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(f.keyCount))   // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], uint64(f.nodeCount))  // bt_node_count
}

// putRecord lays out one variable-size (key, value) pair in a file-system tree node:
// the key grows forward from the key area, the value backward from the value
// area, and a kvloc TOC entry records their offsets and lengths.
func (c *fsTreeCursor) putRecord(key, val []byte) {
	kStart := c.keyOff
	copy(c.block[c.keyOff:], key)
	c.keyOff += len(key)

	valOff := c.valEnd - len(val)
	copy(c.block[valOff:], val)
	vOff := c.valAreaEnd - c.valEnd + len(val)
	c.valEnd -= len(val)

	c.putKvloc(uint16(kStart-c.keyArea), uint16(len(key)), uint16(vOff), uint16(len(val)))
	c.tocOff += sizeofKvloc
}
