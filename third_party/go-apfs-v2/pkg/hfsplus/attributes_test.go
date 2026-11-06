package hfsplus

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Attribute fixtures are synthesized rather than committed, because this
// package's writer emits no attributes file yet: there is nothing that could
// produce one to commit. buildBTree is the writer's own tree builder, so the
// records below are laid out exactly as a real volume's would be.

// forkAttrRecord builds a kHFSPlusAttrForkData payload describing a fork of
// logicalSize bytes living at the given extents.
func forkAttrRecord(logicalSize uint64, totalBlocks uint32, extents ...ExtentDescriptor) []byte {
	payload := make([]byte, 8+80)
	binary.BigEndian.PutUint32(payload[0:], attrForkData)
	binary.BigEndian.PutUint64(payload[8:], logicalSize)
	binary.BigEndian.PutUint32(payload[20:], totalBlocks)
	for i, ext := range extents {
		binary.BigEndian.PutUint32(payload[24+i*8:], ext.StartBlock)
		binary.BigEndian.PutUint32(payload[24+i*8+4:], ext.BlockCount)
	}
	return payload
}

// extentsAttrRecord builds a kHFSPlusAttrExtents payload.
func extentsAttrRecord(extents ...ExtentDescriptor) []byte {
	payload := make([]byte, 8+64)
	binary.BigEndian.PutUint32(payload[0:], attrExtents)
	for i, ext := range extents {
		binary.BigEndian.PutUint32(payload[8+i*8:], ext.StartBlock)
		binary.BigEndian.PutUint32(payload[8+i*8+4:], ext.BlockCount)
	}
	return payload
}

// attrVolume builds a Volume whose attributes file holds recs, with dataBlocks
// laid out after the tree so a fork-data attribute has somewhere to point.
// Block size equals node size, and the tree starts at block 1.
func attrVolume(t *testing.T, nodeSize int, recs []btRecord, dataBlocks []byte) *Volume {
	t.Helper()

	tree := buildBTree(nodeSize, recs, HFSBinaryCompare, 0x06, 266, 0)

	treeBytes := make([]byte, 0, len(tree.nodes)*nodeSize)
	for _, node := range tree.nodes {
		treeBytes = append(treeBytes, node...)
	}

	// Block 0 is unused; the tree occupies blocks 1..n; data follows.
	dev := make([]byte, nodeSize)
	dev = append(dev, treeBytes...)
	dev = append(dev, dataBlocks...)

	v := &Volume{
		dev:       bytes.NewReader(dev),
		blockSize: int64(nodeSize),
	}
	v.hdr.AttributesFile = ForkData{
		LogicalSize: uint64(len(treeBytes)),
		TotalBlocks: uint32(len(tree.nodes)),
		Extents: ExtentRecord{
			{StartBlock: 1, BlockCount: uint32(len(tree.nodes))},
		},
	}
	return v
}

func TestAttributesInlineValues(t *testing.T) {
	const fileID = CatalogNodeID(20)

	recs := []btRecord{
		{key: encodeAttrKey(fileID, "com.apple.FinderInfo", 0), payload: attrInlineRecord(bytes.Repeat([]byte{0xAB}, 32))},
		{key: encodeAttrKey(fileID, "com.example.test", 0), payload: attrInlineRecord([]byte("value42"))},
		{key: encodeAttrKey(fileID+1, "com.example.other", 0), payload: attrInlineRecord([]byte("elsewhere"))},
	}

	v := attrVolume(t, 512, recs, nil)
	if err := v.loadAttributes(); err != nil {
		t.Fatalf("loadAttributes: %v", err)
	}

	got, err := v.attributeValue(fileID, "com.example.test")
	if err != nil {
		t.Fatalf("attributeValue: %v", err)
	}
	if string(got) != "value42" {
		t.Errorf("com.example.test = %q, want %q", got, "value42")
	}

	if names := v.attrNames[fileID]; len(names) != 2 {
		t.Errorf("file %d has attributes %v, want 2", fileID, names)
	}

	// Attributes must not leak between files.
	if _, err := v.attributeValue(fileID, "com.example.other"); err == nil {
		t.Error("an attribute of a different file was returned")
	}
}

// TestAttributesDoNotAliasAcrossNodes is the regression test for the sharpest
// hazard in this code: walkLeaves reuses one buffer for every node it reads and
// hands the visitor sub-slices of it. An attribute loader that retained those
// slices would have every value silently become the last node's bytes. The
// records here are sized so they cannot fit in one node.
func TestAttributesDoNotAliasAcrossNodes(t *testing.T) {
	const (
		fileID   = CatalogNodeID(30)
		nodeSize = 512
		count    = 24
	)

	// Each value is distinct and large enough that a few records fill a node.
	want := make(map[string][]byte, count)
	recs := make([]btRecord, 0, count)
	for i := range count {
		name := string(rune('a'+i)) + ".attr"
		value := bytes.Repeat([]byte{byte(i + 1)}, 100)
		want[name] = value
		recs = append(recs, btRecord{key: encodeAttrKey(fileID, name, 0), payload: attrInlineRecord(value)})
	}

	v := attrVolume(t, nodeSize, recs, nil)
	if err := v.loadAttributes(); err != nil {
		t.Fatalf("loadAttributes: %v", err)
	}

	for name, expected := range want {
		got, err := v.attributeValue(fileID, name)
		if err != nil {
			t.Fatalf("attributeValue(%q): %v", name, err)
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("attribute %q = %x..., want %x... (values aliased across B-tree nodes)",
				name, got[:min(4, len(got))], expected[:4])
		}
	}
}

func TestAttributesForkBacked(t *testing.T) {
	const (
		fileID   = CatalogNodeID(40)
		nodeSize = 512
	)

	// A value spanning two allocation blocks, stored in a fork of its own.
	value := bytes.Repeat([]byte("fork-backed attribute value. "), 30)[:700]
	data := make([]byte, 2*nodeSize)
	copy(data, value)

	// The tree occupies blocks 1..n, so the data begins at block 1+n. With one
	// header node and one leaf that is block 3.
	recs := []btRecord{
		{key: encodeAttrKey(fileID, "com.example.big", 0),
			payload: forkAttrRecord(uint64(len(value)), 2, ExtentDescriptor{StartBlock: 3, BlockCount: 2})},
	}

	v := attrVolume(t, nodeSize, recs, data)
	if err := v.loadAttributes(); err != nil {
		t.Fatalf("loadAttributes: %v", err)
	}

	got, err := v.attributeValue(fileID, "com.example.big")
	if err != nil {
		t.Fatalf("attributeValue: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("fork-backed attribute did not round-trip (%d bytes, want %d)", len(got), len(value))
	}
}

// TestAttributesOverflowExtents covers a fork too fragmented for its eight
// inline extents. The spilled extents live in this tree keyed by the same
// (file, name) with a non-zero start block -- not in the extents overflow file.
func TestAttributesOverflowExtents(t *testing.T) {
	const (
		fileID   = CatalogNodeID(50)
		nodeSize = 512
	)

	// Nine single-block extents: eight fit inline, the ninth must come from an
	// extents record.
	const blocks = 9
	value := make([]byte, blocks*nodeSize)
	for i := range value {
		value[i] = byte(i)
	}

	// Tree is header + one leaf + one leaf for the extents record... buildBTree
	// packs both records into one leaf, so data starts at block 3.
	const dataStart = 3
	var inline [8]ExtentDescriptor
	for i := range inline {
		inline[i] = ExtentDescriptor{StartBlock: uint32(dataStart + i), BlockCount: 1}
	}

	recs := []btRecord{
		{key: encodeAttrKey(fileID, "com.example.frag", 0),
			payload: forkAttrRecord(uint64(len(value)), blocks, inline[:]...)},
		{key: encodeAttrKey(fileID, "com.example.frag", 8),
			payload: extentsAttrRecord(ExtentDescriptor{StartBlock: dataStart + 8, BlockCount: 1})},
	}

	v := attrVolume(t, nodeSize, recs, value)
	if err := v.loadAttributes(); err != nil {
		t.Fatalf("loadAttributes: %v", err)
	}

	got, err := v.attributeValue(fileID, "com.example.frag")
	if err != nil {
		t.Fatalf("attributeValue: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("fragmented attribute did not round-trip (%d bytes, want %d)", len(got), len(value))
	}

	// The name must appear once, not once per record.
	if names := v.attrNames[fileID]; len(names) != 1 {
		t.Errorf("attribute names = %v, want exactly one", names)
	}
}

func TestAttributesRejectOversizedInlineRecord(t *testing.T) {
	const fileID = CatalogNodeID(60)

	// attrSize claims more than the record can hold.
	payload := make([]byte, 16+4)
	binary.BigEndian.PutUint32(payload[0:], attrInlineData)
	binary.BigEndian.PutUint32(payload[12:], 4096)

	v := attrVolume(t, 512, []btRecord{{key: encodeAttrKey(fileID, "bad", 0), payload: payload}}, nil)
	if err := v.loadAttributes(); err == nil {
		t.Fatal("an inline record claiming more bytes than it holds was accepted")
	}
}

func TestAttributesEmptyWhenNoAttributesFile(t *testing.T) {
	v := &Volume{dev: bytes.NewReader(make([]byte, 512)), blockSize: 512}
	if err := v.loadAttributes(); err != nil {
		t.Fatalf("loadAttributes on a volume with no attributes file: %v", err)
	}
	if len(v.attributes) != 0 {
		t.Errorf("found %d attributes on a volume with no attributes file", len(v.attributes))
	}
}
