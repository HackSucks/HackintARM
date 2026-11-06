// Writing the attributes file: encoding attribute B-tree keys and records.
//
// The header constants here are not guesses. They were read off a volume macOS
// created (`testdata/cli/hfs-basic.dmg`), whose attributes B-tree header
// carries maxKeyLength 266, attributes 0x06 and keyCompareType 0x00 -- the last
// notably *not* one of the catalog's compare types, because attribute names are
// compared as plain UTF-16 code units.
package hfsplus

import (
	"encoding/binary"
	"unicode/utf16"
)

const (
	// attrMaxKeyLength is kHFSPlusAttrMaxKeyLength: the fixed part plus a
	// 127-code-unit name.
	attrMaxKeyLength = 266

	// attrTreeAttributes is kBTBigKeysMask | kBTVariableIndexKeysMask, matching
	// the catalog and what macOS writes for this tree.
	attrTreeAttributes = 0x00000006
)

// encodeAttrKey builds an attributes B-tree key with its keyLength prefix:
// keyLength(2) pad(2) fileID(4) startBlock(4) nameLength(2) name(UTF-16BE).
func encodeAttrKey(fileID CatalogNodeID, name string, startBlock uint32) []byte {
	units := utf16.Encode([]rune(name))
	keyLen := attrKeyMinLen + 2*len(units) // bytes after the keyLength field
	b := make([]byte, 2+keyLen)
	binary.BigEndian.PutUint16(b[0:], uint16(keyLen))
	// b[2:4] is the pad, left zero.
	binary.BigEndian.PutUint32(b[4:], uint32(fileID))
	binary.BigEndian.PutUint32(b[8:], startBlock)
	binary.BigEndian.PutUint16(b[12:], uint16(len(units)))
	for i, u := range units {
		binary.BigEndian.PutUint16(b[14+2*i:], u)
	}
	return b
}

// attrKeyFields extracts the ordering fields from an encoded key (keyLength
// prefix included).
func attrKeyFields(key []byte) (CatalogNodeID, []uint16, uint32) {
	fileID := CatalogNodeID(binary.BigEndian.Uint32(key[4:]))
	startBlock := binary.BigEndian.Uint32(key[8:])
	nameLen := int(binary.BigEndian.Uint16(key[12:]))
	units := make([]uint16, nameLen)
	for i := range units {
		units[i] = binary.BigEndian.Uint16(key[14+2*i:])
	}
	return fileID, units, startBlock
}

// compareAttrKeys orders two encoded attribute keys: file id, then name, then
// start block. Names are compared as UTF-16 code units, which is what
// keyCompareType 0 means for this tree -- no case folding, unlike the catalog.
func compareAttrKeys(a, b []byte) int {
	fa, na, sa := attrKeyFields(a)
	fb, nb, sb := attrKeyFields(b)
	if fa != fb {
		if fa < fb {
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
	if len(na) != len(nb) {
		if len(na) < len(nb) {
			return -1
		}
		return 1
	}
	if sa != sb {
		if sa < sb {
			return -1
		}
		return 1
	}
	return 0
}

// attrInlineRecord builds a kHFSPlusAttrInlineData payload: the value lives
// inside the record itself.
func attrInlineRecord(value []byte) []byte {
	payload := make([]byte, 16+len(value))
	binary.BigEndian.PutUint32(payload[0:], attrInlineData)
	binary.BigEndian.PutUint32(payload[12:], uint32(len(value)))
	copy(payload[16:], value)
	if len(payload)%2 == 1 {
		// Keep the next record's key 2-byte aligned, as walkLeaves assumes.
		payload = append(payload, 0)
	}
	return payload
}

// attrForkRecord builds a kHFSPlusAttrForkData payload: the value lives in an
// allocation extent of its own.
func attrForkRecord(fork ForkData) []byte {
	payload := make([]byte, 8+80)
	binary.BigEndian.PutUint32(payload[0:], attrForkData)
	binary.BigEndian.PutUint64(payload[8:], fork.LogicalSize)
	binary.BigEndian.PutUint32(payload[16:], fork.ClumpSize)
	binary.BigEndian.PutUint32(payload[20:], fork.TotalBlocks)
	for i, ext := range fork.Extents {
		binary.BigEndian.PutUint32(payload[24+i*8:], ext.StartBlock)
		binary.BigEndian.PutUint32(payload[24+i*8+4:], ext.BlockCount)
	}
	return payload
}

// maxInlineAttrSize is the largest value stored inside its own record; anything
// bigger gets a fork.
//
// A leaf record and its offset-table entry must fit in a node, and a tree whose
// leaves hold a single record each degenerates, so the ceiling is set at half a
// node less the largest possible key and the record header. Values above it are
// not refused -- they simply take the fork path instead.
func maxInlineAttrSize(nodeSize int) int {
	limit := nodeSize/2 - attrMaxKeyLength - 16 - 4
	if limit < 0 {
		return 0
	}
	return limit
}
