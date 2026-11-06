// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"fmt"
)

// B-trees of any height are built bottom-up. The sorted records are packed into
// leaves; each leaf contributes one index record -- its first key and a pointer
// to it -- and those are packed into the level above, and so on until a single
// node holds them all. That node is the root, and only the root carries the
// btree_info footer, so every level first tries to fit in one root-sized node
// before it splits.
//
// A child pointer is eight bytes whatever it names (a virtual oid in the
// file-system tree, a block number in the physical trees), so a tree's shape is
// fixed by its record sizes alone. That is what lets the shape be decided while
// the volume is planned, before any block has been placed, and be reproduced
// exactly when the tree is written.
//
// Non-root nodes are numbered from the leaves up, left to right. A tree's j'th
// non-root node is placed at the j'th block of the region reserved for it; the
// root keeps its fixed block. A two-level tree therefore lays out as it always
// has -- leaf i at block i of the region -- and only taller trees are new.

// childPtrSize is the size of an index record's value: an oid or a block number.
const childPtrSize = 8

// varNodeBytes is the space one node of variable-size records needs: header,
// table of contents, keys, values and, for the root, the footer.
func varNodeBytes(recs []fsTreeRecord, footer int) int {
	n := sizeofBtreeNodePhys + tocBytesFor(len(recs)) + footer
	for _, r := range recs {
		n += len(r.key) + len(r.val)
	}
	return n
}

// varTreeLevels packs sorted records into the levels of a B-tree whose nodes
// hold variable-size records, from the leaves up. The last level is the root,
// alone. Index records are fresh copies whose values are left for writeVarTree
// to fill with child pointers.
func varTreeLevels(recs []fsTreeRecord, blocksize int) ([][][]fsTreeRecord, error) {
	var levels [][][]fsTreeRecord
	for {
		if varNodeBytes(recs, sizeofBtreeInfo) <= blocksize {
			return append(levels, [][]fsTreeRecord{recs}), nil
		}
		nodes := packFSTreeLeaves(recs, blocksize, 0)
		for _, n := range nodes {
			if need := varNodeBytes(n, 0); need > blocksize {
				return nil, fmt.Errorf("apfswrite: a B-tree record needs %d bytes, more than one %d-byte node", need, blocksize)
			}
		}
		// Every index level must be narrower than the one below it, or the
		// tree would never close into a root.
		if len(levels) > 0 && len(nodes) >= len(recs) {
			return nil, fmt.Errorf("apfswrite: B-tree index level of %d records does not pack into fewer nodes", len(recs))
		}
		levels = append(levels, nodes)

		index := make([]fsTreeRecord, len(nodes))
		for i, n := range nodes {
			index[i] = n[0]
			index[i].val = make([]byte, childPtrSize)
		}
		recs = index
	}
}

// treeNodeCount returns how many nodes a tree of these levels has.
func treeNodeCount[T any](levels [][]T) int {
	n := 0
	for _, level := range levels {
		n += len(level)
	}
	return n
}

// varTreeSpec says how one variable-record tree is stored: where its root and
// its other nodes go, what they are called, and how the root's footer reads.
type varTreeSpec struct {
	rootPaddr, rootOID uint64
	// nodePaddr and nodeOID place and name the j'th non-root node. A physical
	// tree's nodes are named by their block numbers.
	nodePaddr func(j uint64) uint64
	nodeOID   func(j uint64) uint64
	// childPtr is what an index record stores to reach the j'th non-root node:
	// its oid in a virtual tree, its block number in a physical one.
	childPtr func(j uint64) uint64
	storage  uint32 // objVirtual or objPhysical
	subtype  uint32
	footer   func(info []byte, nodeCount int)
}

// writeVarTree writes a tree packed by varTreeLevels.
func (b *builder) writeVarTree(levels [][][]fsTreeRecord, s varTreeSpec) error {
	nodeCount := treeNodeCount(levels)
	var j uint64       // the next non-root node's number
	var below []uint64 // numbers of the level below's nodes, in order
	for li, level := range levels {
		isRoot := li == len(levels)-1
		var here []uint64
		child := 0
		for _, recs := range level {
			// An index node's records point at the level below, in order.
			if li > 0 {
				for k := range recs {
					binary.LittleEndian.PutUint64(recs[k].val, s.childPtr(below[child]))
					child++
				}
			}
			paddr, oid := s.rootPaddr, s.rootOID
			if !isRoot {
				paddr, oid = s.nodePaddr(j), s.nodeOID(j)
				here = append(here, j)
				j++
			}
			var footer func([]byte)
			if isRoot {
				footer = func(info []byte) { s.footer(info, nodeCount) }
			}
			if err := b.writeVarNode(paddr, oid, recs, uint16(li), footer, s.storage, s.subtype); err != nil {
				return err
			}
		}
		below = here
	}
	return nil
}

// writeVarNode writes one node of variable-size records at level. A non-nil
// footer marks the root, which carries the btree_info trailer; a node at level
// zero is a leaf.
func (b *builder) writeVarNode(paddr, oid uint64, recs []fsTreeRecord, level uint16, footer func([]byte), storage, subtype uint32) error {
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := 0
	var flags uint16
	if level == 0 {
		flags |= btnodeLeaf
	}
	if footer != nil {
		flags |= btnodeRoot
		infoLen = sizeofBtreeInfo
	}
	if need := varNodeBytes(recs, infoLen); need > int(b.blocksize) {
		return fmt.Errorf("apfswrite: B-tree node needs %d bytes, more than one %d-byte block", need, b.blocksize)
	}
	binary.LittleEndian.PutUint16(block[btnOffFlags:], flags)
	binary.LittleEndian.PutUint16(block[btnOffLevel:], level)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(len(recs)))

	tocLen := tocBytesFor(len(recs))
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))

	cur := &fsTreeCursor{
		b:          b,
		block:      block,
		tocOff:     headLen,
		keyArea:    headLen + tocLen,
		keyOff:     headLen + tocLen,
		valAreaEnd: int(b.blocksize) - infoLen,
		valEnd:     int(b.blocksize) - infoLen,
	}
	for _, r := range recs {
		cur.putRecord(r.key, r.val)
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(block, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)

	objType := uint32(objectTypeBtreeNode) | storage
	if footer != nil {
		objType = objectTypeBtree | storage
		footer(block[int(b.blocksize)-infoLen:])
	}
	setObjectHeader(block, int(b.blocksize), oid, objType, subtype)
	return b.writeBlock(block, paddr)
}

// Object maps are fixed-layout trees. A leaf record is an omap_key_t and an
// omap_val_t; an index record is the same key and the child's block number.

// omapNodeLayout returns the table-of-contents size and record capacity of one
// object-map node. The table of contents is sized, as for every fixed-layout
// node here, to index as many records as the node body could hold if packed
// solid; the capacity is then whatever fits beside it and, in the root, the
// footer.
func (b *builder) omapNodeLayout(leaf, root bool) (tocLen, capacity int) {
	valSize := sizeofOmapVal
	if !leaf {
		valSize = childPtrSize
	}
	body := int(b.blocksize) - sizeofBtreeNodePhys
	tocLen = (body / (sizeofOmapKey + valSize + sizeofKvoff)) * sizeofKvoff
	footer := 0
	if root {
		footer = sizeofBtreeInfo
	}
	capacity = min(tocLen/sizeofKvoff, (body-tocLen-footer)/(sizeofOmapKey+valSize))
	return tocLen, capacity
}

// omapLevelSizes returns how many nodes each level of an object map holding n
// mappings has, from the leaves up. The last level is the root, alone.
func (b *builder) omapLevelSizes(n int) []int {
	var sizes []int
	leaf := true
	for {
		if _, rootCap := b.omapNodeLayout(leaf, true); n <= rootCap {
			return append(sizes, 1)
		}
		_, capacity := b.omapNodeLayout(leaf, false)
		nodes := int(divRoundUp(uint64(n), uint64(capacity)))
		sizes = append(sizes, nodes)
		n, leaf = nodes, false
	}
}

// omapNodeCount returns how many nodes an object map of n mappings has.
func (b *builder) omapNodeCount(n int) int {
	total := 0
	for _, s := range b.omapLevelSizes(n) {
		total += s
	}
	return total
}

// omapRecord is one record of an object-map node: its key, and either the
// mapping it holds (in a leaf) or the block of the child it points at.
type omapRecord struct {
	oid, xid uint64
	entry    omapEntry // leaf records
	child    uint64    // index records
}

// writeOmapTree writes an object map's tree of entries, sorted by oid. The root
// goes at rootPaddr and the j'th other node at nodePaddr(j).
func (b *builder) writeOmapTree(rootPaddr uint64, nodePaddr func(j uint64) uint64, entries []omapEntry, xid uint64) error {
	sizes := b.omapLevelSizes(len(entries))
	nodeCount := 0
	for _, s := range sizes {
		nodeCount += s
	}

	recs := make([]omapRecord, len(entries))
	for i, e := range entries {
		recs[i] = omapRecord{oid: e.oid, xid: e.xid, entry: e}
	}

	var j uint64
	for li, nodes := range sizes {
		leaf, root := li == 0, li == len(sizes)-1
		_, capacity := b.omapNodeLayout(leaf, root)
		var up []omapRecord
		for n := range nodes {
			chunk := recs[n*capacity : min((n+1)*capacity, len(recs))]
			paddr := rootPaddr
			if !root {
				paddr = nodePaddr(j)
				j++
			}
			if err := b.writeOmapNode(paddr, uint16(li), root, chunk, len(entries), nodeCount, xid); err != nil {
				return err
			}
			up = append(up, omapRecord{oid: chunk[0].oid, xid: chunk[0].xid, child: paddr})
		}
		recs = up
	}
	return nil
}

// writeOmapNode writes one object-map node. Keys pack forward from the end of
// the table of contents and values pack backward from the end of the value
// area, which for the root is the start of its footer.
func (b *builder) writeOmapNode(paddr uint64, level uint16, root bool, recs []omapRecord, keyCount, nodeCount int, xid uint64) error {
	leaf := level == 0
	tocLen, capacity := b.omapNodeLayout(leaf, root)
	if len(recs) > capacity {
		return fmt.Errorf("apfswrite: object-map node holds %d records, more than its %d", len(recs), capacity)
	}
	valSize := sizeofOmapVal
	if !leaf {
		valSize = childPtrSize
	}

	block := b.zeroedBlock()
	infoLen := 0
	flags := uint16(btnodeFixedKVSize)
	if leaf {
		flags |= btnodeLeaf
	}
	if root {
		flags |= btnodeRoot
		infoLen = sizeofBtreeInfo
	}
	keyArea := sizeofBtreeNodePhys + tocLen
	valAreaEnd := int(b.blocksize) - infoLen

	for i, r := range recs {
		toc := sizeofBtreeNodePhys + i*sizeofKvoff
		keyOff := keyArea + i*sizeofOmapKey
		valOff := valAreaEnd - (i+1)*valSize
		binary.LittleEndian.PutUint16(block[toc:], uint16(keyOff-keyArea))
		binary.LittleEndian.PutUint16(block[toc+2:], uint16(valAreaEnd-valOff))

		binary.LittleEndian.PutUint64(block[keyOff:], r.oid)   // ok_oid
		binary.LittleEndian.PutUint64(block[keyOff+8:], r.xid) // ok_xid
		if leaf {
			binary.LittleEndian.PutUint32(block[valOff:], r.entry.flags)   // ov_flags
			binary.LittleEndian.PutUint32(block[valOff+4:], b.blocksize)   // ov_size
			binary.LittleEndian.PutUint64(block[valOff+8:], r.entry.paddr) // ov_paddr
		} else {
			binary.LittleEndian.PutUint64(block[valOff:], r.child) // child block
		}
	}

	nkeys := len(recs)
	usedKeys := nkeys * sizeofOmapKey
	usedVals := nkeys * valSize
	freeLen := int(b.blocksize) - sizeofBtreeNodePhys - tocLen - usedKeys - usedVals - infoLen
	writeLeafHeader(block, flags, nkeys, tocLen, usedKeys, freeLen)
	binary.LittleEndian.PutUint16(block[btnOffLevel:], level)

	objType := uint32(objectTypeBtreeNode) | objPhysical
	if root {
		objType = objectTypeBtree | objPhysical
		b.writeOmapFooter(block[int(b.blocksize)-infoLen:], keyCount, nodeCount)
	}
	// A node may not be older than the newest key it holds: the container omap
	// maps the live volume superblock at the live transaction id, so once that
	// id is raised past the snapshots the node has to be raised with it.
	// apfsck: "Object map: node xid is older than key xid".
	setObjectHeaderXID(block, int(b.blocksize), paddr, objType, objectTypeOmap, xid)
	return b.writeBlock(block, paddr)
}
