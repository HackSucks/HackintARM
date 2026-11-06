// B-tree writing: serialisation of catalog and extents-overflow B-tree
// nodes for the HFS+/HFSX writer. Produces node byte images with the
// standard descriptor, packed records and a downward-growing offset table
// (see TN1150). All multi-byte fields are big-endian.
//
// The catalog tree is built as a bottom-up B-tree: leaf records are packed
// in key order into leaf nodes, then index levels are added until a single
// root node remains. This handles trees of any size (single-leaf trees keep
// treeDepth == 1).
package hfsplus

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// marshalBE serialises a fixed-layout struct as big-endian bytes.
func marshalBE(v any) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
		// All callers pass fixed-size structs; a failure is a programming bug.
		panic("hfsplus: marshalBE: " + err.Error())
	}
	return buf.Bytes()
}

// packNode assembles one B-tree node image of nodeSize bytes: a 14-byte
// descriptor, the raw record contents packed from offset 14 upward, and an
// offset table growing downward from the node tail (R+1 entries; the last
// two bytes hold record 0's offset, and slot R holds the free-space offset).
func packNode(nodeSize int, kind BTreeNodeKind, height uint8, fLink, bLink uint32, records [][]byte) []byte {
	buf := make([]byte, nodeSize)

	desc := BTNodeDescriptor{
		FLink:      fLink,
		BLink:      bLink,
		Kind:       kind,
		Height:     height,
		NumRecords: uint16(len(records)),
	}
	copy(buf, marshalBE(&desc))

	offset := 14
	offsets := make([]int, 0, len(records)+1)
	for _, rec := range records {
		offsets = append(offsets, offset)
		copy(buf[offset:], rec)
		offset += len(rec)
	}
	offsets = append(offsets, offset) // free-space offset

	// Offset table: record i's offset at nodeSize-2*(i+1).
	for i, off := range offsets {
		binary.BigEndian.PutUint16(buf[nodeSize-2*(i+1):], uint16(off))
	}
	return buf
}

// encodeUTF16 returns the UTF-16 code units of a Go string.
func encodeUTF16(name string) []uint16 {
	return utf16.Encode([]rune(name))
}

// encodeCatalogKey builds a catalog B-tree key (keyLength prefix included):
// keyLength(2) parentID(4) nameLength(2) name(UTF-16BE code units).
func encodeCatalogKey(parentID CatalogNodeID, name string) []byte {
	units := encodeUTF16(name)
	nameLen := len(units)
	keyLen := 6 + 2*nameLen // bytes after the keyLength field
	b := make([]byte, 2+keyLen)
	binary.BigEndian.PutUint16(b[0:], uint16(keyLen))
	binary.BigEndian.PutUint32(b[2:], uint32(parentID))
	binary.BigEndian.PutUint16(b[6:], uint16(nameLen))
	for i, u := range units {
		binary.BigEndian.PutUint16(b[8+2*i:], u)
	}
	return b
}

// catalogKeyFields extracts (parentID, UTF-16 name units) from an encoded
// catalog key (with the keyLength prefix) for ordering comparisons.
func catalogKeyFields(key []byte) (CatalogNodeID, []uint16) {
	parentID := CatalogNodeID(binary.BigEndian.Uint32(key[2:]))
	nameLen := int(binary.BigEndian.Uint16(key[6:]))
	units := make([]uint16, nameLen)
	for i := range units {
		units[i] = binary.BigEndian.Uint16(key[8+2*i:])
	}
	return parentID, units
}

// compareCatalogKeysFolded orders two encoded catalog keys the way a
// case-insensitive volume does: parent id ascending, then the name compared
// through the fold table, skipping code units the fold ignores.
func compareCatalogKeysFolded(a, b []byte) int {
	pa, na := catalogKeyFields(a)
	pb, nb := catalogKeyFields(b)
	if pa != pb {
		if pa < pb {
			return -1
		}
		return 1
	}
	// Apple CompareExtendedCatalogKeys reserves empty names for thread keys.
	// An all-ignorable filename must not compare equal to its folder thread.
	if len(na) == 0 || len(nb) == 0 {
		return len(na) - len(nb)
	}
	i, j := 0, 0
	for {
		var ua, ub uint16
		var oka, okb bool
		for i < len(na) && !oka {
			ua, oka = foldUnit(na[i])
			i++
		}
		for j < len(nb) && !okb {
			ub, okb = foldUnit(nb[j])
			j++
		}
		if !oka || !okb {
			switch {
			case oka:
				return 1
			case okb:
				return -1
			default:
				return 0
			}
		}
		if ua != ub {
			if ua < ub {
				return -1
			}
			return 1
		}
	}
}

// compareCatalogKeys orders two encoded catalog keys with HFSX binary
// comparison: parentID ascending, then lexicographic on the big-endian
// UTF-16 name code units. Returns <0, 0 or >0.
func compareCatalogKeys(a, b []byte) int {
	pa, na := catalogKeyFields(a)
	pb, nb := catalogKeyFields(b)
	if pa != pb {
		if pa < pb {
			return -1
		}
		return 1
	}
	for i := 0; i < len(na) && i < len(nb); i++ {
		if na[i] != nb[i] {
			if na[i] < nb[i] {
				return -1
			}
			return 1
		}
	}
	return len(na) - len(nb)
}

// btRecord is one B-tree record awaiting placement: its key bytes (with the
// keyLength prefix) and its payload (record body for leaves, child node
// number for index records).
type btRecord struct {
	key     []byte
	payload []byte
}

// bytes returns the on-disk record image: key followed by payload. Both are
// even-length for catalog records, so the payload stays 2-byte aligned.
func (r btRecord) bytes() []byte {
	out := make([]byte, len(r.key)+len(r.payload))
	copy(out, r.key)
	copy(out[len(r.key):], r.payload)
	return out
}

// builtTree is the serialised result of buildBTree.
type builtTree struct {
	nodes         [][]byte // nodes[i] is node i's byte image (node 0 = header)
	treeDepth     uint16
	rootNode      uint32
	leafRecords   uint32
	firstLeafNode uint32
	lastLeafNode  uint32
	totalNodes    uint32
	freeNodes     uint32
}

// buildBTree constructs a complete B-tree (header node + leaf/index nodes)
// from leaf records already sorted in key order. keyCompareType and
// attributes/maxKeyLength are written into the header record. When there are
// no leaf records the tree is header-only (empty), matching the extents
// overflow file's expected shape.
//
// spareNodes free nodes are appended after the used nodes so the on-disk fork
// has room to grow (freeNodes reflects them).
func buildBTree(nodeSize int, leafRecs []btRecord, keyCompareType BTHeaderKeyCompareType, attributes uint32, maxKeyLength uint16, spareNodes int) builtTree {
	// Node 0 is always the header; real nodes are numbered from 1.
	var nodeImages [][]byte // index 0 == node 1
	var result builtTree

	if len(leafRecs) == 0 {
		result.treeDepth = 0
		result.rootNode = 0
		result.firstLeafNode = 0
		result.lastLeafNode = 0
	} else {
		// Pack leaf records into leaf nodes preserving order.
		leafChunks := chunkRecords(nodeSize, leafRecs)
		firstLeaf := uint32(1)
		lastLeaf := uint32(len(leafChunks))

		// Assign node numbers level by level. Leaves get 1..L.
		type levelNode struct {
			num   uint32
			first []byte // first key of the node (for the parent index)
			recs  []btRecord
			kind  BTreeNodeKind
		}

		var leaves []levelNode
		for i, chunk := range leafChunks {
			leaves = append(leaves, levelNode{
				num:   uint32(i + 1),
				first: chunk[0].key,
				recs:  chunk,
				kind:  BTLeafNodeKind,
			})
		}

		// Serialise leaf nodes with sibling links.
		nodeImages = make([][]byte, len(leaves))
		for i, ln := range leaves {
			var fLink, bLink uint32
			if i+1 < len(leaves) {
				fLink = leaves[i+1].num
			}
			if i > 0 {
				bLink = leaves[i-1].num
			}
			records := make([][]byte, len(ln.recs))
			for j, r := range ln.recs {
				records[j] = r.bytes()
			}
			nodeImages[ln.num-1] = packNode(nodeSize, BTLeafNodeKind, 1, fLink, bLink, records)
		}

		// Build index levels bottom-up until a single node remains.
		curLevel := leaves
		height := uint8(1)
		nextNum := uint32(len(leaves) + 1)
		for len(curLevel) > 1 {
			height++
			// Index records: one per child, key = child's first key,
			// payload = child node number.
			idxRecs := make([]btRecord, len(curLevel))
			for i, child := range curLevel {
				var childNum [4]byte
				binary.BigEndian.PutUint32(childNum[:], child.num)
				idxRecs[i] = btRecord{key: child.first, payload: childNum[:]}
			}
			idxChunks := chunkRecords(nodeSize, idxRecs)

			var idxNodes []levelNode
			for _, chunk := range idxChunks {
				idxNodes = append(idxNodes, levelNode{
					num:   nextNum,
					first: chunk[0].key,
					recs:  chunk,
					kind:  BTIndexNodeKind,
				})
				nextNum++
			}
			// Serialise index nodes with sibling links.
			for i, in := range idxNodes {
				var fLink, bLink uint32
				if i+1 < len(idxNodes) {
					fLink = idxNodes[i+1].num
				}
				if i > 0 {
					bLink = idxNodes[i-1].num
				}
				records := make([][]byte, len(in.recs))
				for j, r := range in.recs {
					records[j] = r.bytes()
				}
				img := packNode(nodeSize, BTIndexNodeKind, height, fLink, bLink, records)
				for uint32(len(nodeImages)) < in.num {
					nodeImages = append(nodeImages, nil)
				}
				nodeImages[in.num-1] = img
			}
			curLevel = idxNodes
		}

		result.treeDepth = uint16(height)
		result.rootNode = curLevel[0].num
		result.firstLeafNode = firstLeaf
		result.lastLeafNode = lastLeaf
		result.leafRecords = uint32(len(leafRecs))
	}

	usedNodes := 1 + uint32(len(nodeImages)) // header + real nodes
	totalNodes := usedNodes + uint32(spareNodes)

	// Header node (node 0).
	header := packHeaderNode(nodeSize, result, keyCompareType, attributes, maxKeyLength, totalNodes, usedNodes)

	all := make([][]byte, 0, totalNodes)
	all = append(all, header)
	all = append(all, nodeImages...)
	for uint32(len(all)) < totalNodes {
		all = append(all, make([]byte, nodeSize)) // spare (free) nodes: all zero
	}

	result.nodes = all
	result.totalNodes = totalNodes
	result.freeNodes = totalNodes - usedNodes
	return result
}

// chunkRecords greedily packs records into node-sized groups preserving
// order. Each node reserves 14 bytes for the descriptor and 2 bytes per
// record (plus one) for the offset table.
func chunkRecords(nodeSize int, recs []btRecord) [][]btRecord {
	var chunks [][]btRecord
	var cur []btRecord
	used := 14 + 2 // descriptor + free-space offset slot
	for _, r := range recs {
		recLen := len(r.key) + len(r.payload)
		need := recLen + 2 // record bytes + its offset-table entry
		if len(cur) > 0 && used+need > nodeSize {
			chunks = append(chunks, cur)
			cur = nil
			used = 14 + 2
		}
		cur = append(cur, r)
		used += need
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

// packHeaderNode builds node 0: descriptor + BTHeaderRec + 128-byte user
// record + node-usage bitmap (map record). The map record's bits mark used
// nodes (bit set == in use), MSB-first.
func packHeaderNode(nodeSize int, t builtTree, keyCompareType BTHeaderKeyCompareType, attributes uint32, maxKeyLength uint16, totalNodes, usedNodes uint32) []byte {
	hdr := BTHeaderRec{
		TreeDepth:     t.treeDepth,
		RootNode:      t.rootNode,
		LeafRecords:   t.leafRecords,
		FirstLeafNode: t.firstLeafNode,
		LastLeafNode:  t.lastLeafNode,
		NodeSize:      uint16(nodeSize),
		MaxKeyLength:  maxKeyLength,
		TotalNodes:    totalNodes,
		FreeNodes:     totalNodes - usedNodes,
		// A B-tree file's clump size is its own size. fsck_hfs rejects anything
		// else on a pure HFS+ volume ("Invalid file clump size"), though it
		// does not check this on HFSX.
		ClumpSize:      uint32(totalNodes) * uint32(nodeSize),
		BtreeType:      0,
		KeyCompareType: keyCompareType,
		Attributes:     attributes,
	}
	headerRec := marshalBE(&hdr) // 106 bytes
	userRec := make([]byte, 128) // reserved user data record

	// Map record fills the rest of the node up to the offset table
	// (3 records + 1 free slot => 8 bytes of offsets).
	mapLen := nodeSize - 14 - len(headerRec) - len(userRec) - 2*(3+1)
	mapRec := make([]byte, mapLen)
	for n := uint32(0); n < usedNodes; n++ {
		mapRec[n/8] |= 0x80 >> (n % 8)
	}

	return packNode(nodeSize, BTHeaderNodeKind, 0, 0, 0, [][]byte{headerRec, userRec, mapRec})
}
