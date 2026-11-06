package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func boundaryFSKey(id uint64, kind uint8) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, id|uint64(kind)<<60)
	return b
}
func boundaryFSNode(level uint16, entries ...*BTreeEntry) *BTreeNode {
	flags := uint16(0)
	if level == 0 {
		flags = BTreeNodeFlagLeaf
	}
	return &BTreeNode{NodeHeader: &BTreeNodeHeader{Level: level, Flags: flags}, Entries: entries}
}
func boundaryFSBranch(id, oid uint64) *BTreeEntry {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, oid)
	return &BTreeEntry{KeyData: boundaryFSKey(id, FileSystemRecordTypeInode), ValueData: b}
}

// Traversal fixtures use the real per-reader parsed-node cache. Native image
// tests independently qualify parsing; these fixtures control corruption and
// provider failures at each tree boundary without replacing production methods.
func boundaryFSTree(nodes map[uint64]*BTreeNode) *FileSystemBTree {
	h := &IOHandle{BlockSize: 4096, BytesPerSector: 512}
	omap := &BTreeNode{ObjectType: ObjectMapBTreeRootNodeType, ObjectSubtype: ObjectMapBTreeSubtype, NodeHeader: &BTreeNodeHeader{Flags: 7}, Info: &BTreeInfo{NodeSize: 4096, KeySize: 16, ValueSize: 16}}
	for oid := uint64(100); oid < 120; oid++ {
		k, v := make([]byte, 16), make([]byte, 16)
		binary.LittleEndian.PutUint64(k, oid)
		binary.LittleEndian.PutUint64(k[8:], 1)
		binary.LittleEndian.PutUint64(v[8:], oid-98)
		omap.Entries = append(omap.Entries, &BTreeEntry{KeyData: k, ValueData: v})
	}
	h.putCachedNode(1, omap)
	for oid, node := range nodes {
		h.putCachedNode(oid-98, node)
	}
	return NewFileSystemBTree(h, nil, &ObjectMapBTree{IOHandle: h, RootNodeOID: 1}, 100, 1, true)
}

func TestFileSystemBTreeBoundaryGuards(t *testing.T) {
	r := bytes.NewReader(nil)
	for _, bt := range []*FileSystemBTree{nil, {}, boundaryFSTree(map[uint64]*BTreeNode{})} {
		calls := []func() error{
			func() error { _, e := bt.RootNode(r); return e }, func() error { _, e := bt.SubNode(r, 999); return e }, func() error { _, e := bt.SubNodeOIDFromEntry(r, nil); return e },
			func() error { _, e := bt.AllRecordsForOID(r, 40); return e }, func() error { _, e := bt.FileExtents(r, 40, 1); return e }, func() error { _, e := bt.InodeByIdentifier(r, 40, 1); return e }, func() error { _, e := bt.DirectoryEntries(r, 40, 1); return e }, func() error { _, e := bt.Attributes(r, 40, 1); return e },
			func() error { _, e := bt.EntryFromNodeByIdentifier(nil, 40, 3); return e }, func() error { _, _, e := bt.EntryByIdentifier(r, 40, 3, 1); return e }, func() error { _, e := bt.DirectoryEntryRecordByUTF8Name(r, 40, "x", 1); return e }, func() error { _, e := bt.DirectoryEntryRecordByUTF16Name(r, 40, []uint16{'x'}, 1); return e },
			func() error { _, _, e := bt.InodeByUTF8Name(r, 40, "x", 1); return e }, func() error { _, _, e := bt.InodeByUTF16Name(r, 40, []uint16{'x'}, 1); return e }, func() error { _, _, e := bt.InodeByUTF8Path(r, 40, "x/y", 1); return e }, func() error { _, _, e := bt.InodeByUTF16Path(r, 40, []uint16{'x'}, 1); return e },
		}
		for i, call := range calls {
			if e := call(); e == nil {
				t.Fatalf("invalid tree call%d succeeded", i)
			}
		}
	}
	bt := boundaryFSTree(map[uint64]*BTreeNode{100: boundaryFSNode(0)})
	for _, entry := range []*BTreeEntry{{ValueData: []byte{1}}, boundaryFSBranch(40, 999)} {
		if _, e := bt.SubNodeOIDFromEntry(r, entry); e == nil {
			t.Fatal("invalid child accepted")
		}
	}
	noMap := &FileSystemBTree{}
	if _, e := noMap.SubNodeOIDFromEntry(r, boundaryFSBranch(40, 100)); e == nil {
		t.Fatal("missing object map accepted")
	}
	if _, e := bt.DirectoryEntryRecordByUTF8Name(r, 2, "", 1); e == nil {
		t.Fatal("empty name accepted")
	}
	if _, e := bt.DirectoryEntryRecordByUTF16Name(r, 2, nil, 1); e == nil {
		t.Fatal("empty UTF16 name accepted")
	}
	if _, _, e := bt.InodeByUTF8Path(r, 2, "", 1); e == nil {
		t.Fatal("empty path accepted")
	}
	bt.RootNodeOID = 999
	if _, e := bt.RootNode(r); e == nil {
		t.Fatal("unmapped root accepted")
	}
	bt.ObjectMapBTree.IOHandle = nil
	if _, e := bt.SubNodeOIDFromEntry(r, boundaryFSBranch(40, 100)); e == nil {
		t.Fatal("object-map I/O failure accepted")
	}
}

func TestFileSystemBTreeBoundaryTraversal(t *testing.T) {
	r := bytes.NewReader(nil)
	record := func(id uint64, marker byte) *BTreeEntry {
		return &BTreeEntry{KeyData: boundaryFSKey(id, FileSystemRecordTypeInode), ValueData: []byte{marker}}
	}
	nodes := map[uint64]*BTreeNode{
		100: boundaryFSNode(2, boundaryFSBranch(10, 101), boundaryFSBranch(40, 102)),
		101: boundaryFSNode(1, boundaryFSBranch(10, 103), boundaryFSBranch(40, 104)),
		102: boundaryFSNode(1, boundaryFSBranch(40, 105), boundaryFSBranch(60, 106)),
		103: boundaryFSNode(0, record(10, 1), record(40, 2)), 104: boundaryFSNode(0, record(40, 3)), 105: boundaryFSNode(0, record(40, 4)), 106: boundaryFSNode(0, record(60, 5)),
	}
	bt := boundaryFSTree(nodes)
	got, e := bt.AllRecordsForOID(r, 40)
	if e != nil {
		t.Fatal(e)
	}
	var markers []byte
	for _, v := range got {
		markers = append(markers, v.ValueData[0])
	}
	if !bytes.Equal(markers, []byte{2, 3, 4}) {
		t.Fatalf("cross-interior walk: %v", markers)
	}
	for _, id := range []uint64{1, 50, 90} {
		got, e := bt.AllRecordsForOID(r, id)
		if e != nil || len(got) != 0 {
			t.Fatalf("absent%d: %v %v", id, got, e)
		}
	}
	if node, e := bt.SubNode(r, 103); e != nil || node != nodes[103] {
		t.Fatalf("virtual child fallback: %v", e)
	}
	if _, e := bt.SubNode(r, 119); e == nil {
		t.Fatal("mapped but unreadable child accepted")
	}
	if _, entry, e := bt.EntryByIdentifier(r, 40, FileSystemRecordTypeInode, 1); e != nil || entry == nil {
		t.Fatalf("branch lookup: %v", e)
	}
	for _, tc := range []struct {
		name   string
		change func(map[uint64]*BTreeNode)
	}{
		{"empty-index", func(n map[uint64]*BTreeNode) { n[100] = boundaryFSNode(1) }},
		{"bad-level", func(n map[uint64]*BTreeNode) { n[101] = boundaryFSNode(2, boundaryFSBranch(10, 103)) }},
		{"bad-child-reference", func(n map[uint64]*BTreeNode) { n[100] = boundaryFSNode(1, &BTreeEntry{KeyData: boundaryFSKey(40, 3)}) }},
		{"unreadable-child", func(n map[uint64]*BTreeNode) { n[100] = boundaryFSNode(1, boundaryFSBranch(40, 119)) }},
		{"walk-nonleaf", func(n map[uint64]*BTreeNode) { n[104] = boundaryFSNode(1, boundaryFSBranch(40, 105)) }},
		{"walk-bad-reference", func(n map[uint64]*BTreeNode) {
			n[101] = boundaryFSNode(1, boundaryFSBranch(10, 103), &BTreeEntry{KeyData: boundaryFSKey(40, 3)})
		}},
		{"walk-unreadable-child", func(n map[uint64]*BTreeNode) {
			n[101] = boundaryFSNode(1, boundaryFSBranch(10, 103), boundaryFSBranch(40, 119))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := map[uint64]*BTreeNode{}
			for k, v := range nodes {
				copy[k] = v
			}
			tc.change(copy)
			if _, e := boundaryFSTree(copy).AllRecordsForOID(r, 40); e == nil {
				t.Fatal("corrupt traversal accepted")
			}
		})
	}
}

func TestFileSystemBTreeBoundaryEntrySelection(t *testing.T) {
	bt := &FileSystemBTree{}
	entries := []*BTreeEntry{{KeyData: []byte{1}}, boundaryFSBranch(10, 100), boundaryFSBranch(30, 101)}
	branch := boundaryFSNode(1, entries...)
	for _, tc := range []struct {
		id   uint64
		want int
	}{{1, 1}, {20, 1}, {40, 2}} {
		got, e := bt.EntryFromNodeByIdentifier(branch, tc.id, 3)
		if e != nil || got != entries[tc.want] {
			t.Fatalf("branch%d: %v %v", tc.id, got, e)
		}
	}
	leaf := boundaryFSNode(0, entries...)
	if got, e := bt.EntryFromNodeByIdentifier(leaf, 30, FileSystemRecordTypeAny); e != nil || got != entries[2] {
		t.Fatalf("any type lookup: %v", e)
	}
	if _, e := bt.EntryFromNodeByIdentifier(leaf, 20, 3); e == nil {
		t.Fatal("missing leaf accepted")
	}
	if _, e := bt.EntryFromNodeByIdentifier(boundaryFSNode(1), 20, 3); e == nil {
		t.Fatal("empty branch accepted")
	}
	if got := splitPath("//alpha///beta/"); !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
		t.Fatal(got)
	}
}

func TestFileSystemBTreeBoundaryRecordErrors(t *testing.T) {
	r := bytes.NewReader(nil)
	for _, kind := range []uint8{FileSystemRecordTypeInode, FileSystemRecordTypeDirectoryEntry, FileSystemRecordTypeExtendedAttribute, FileSystemRecordTypeFileExtent} {
		for _, shortKey := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", kind, shortKey), func(t *testing.T) {
				key := boundaryFSKey(40, kind)
				if !shortKey {
					switch kind {
					case FileSystemRecordTypeDirectoryEntry:
						key = append(key, 2, 0, 'x', 0)
					case FileSystemRecordTypeExtendedAttribute:
						key = append(key, 2, 0, 'x', 0)
					case FileSystemRecordTypeFileExtent:
						key = append(key, make([]byte, 8)...)
					}
				}
				bt := boundaryFSTree(map[uint64]*BTreeNode{100: boundaryFSNode(0, &BTreeEntry{KeyData: key})})
				var e error
				switch kind {
				case FileSystemRecordTypeInode:
					_, e = bt.InodeByIdentifier(r, 40, 1)
				case FileSystemRecordTypeDirectoryEntry:
					_, e = bt.DirectoryEntries(r, 40, 1)
				case FileSystemRecordTypeExtendedAttribute:
					_, e = bt.Attributes(r, 40, 1)
				case FileSystemRecordTypeFileExtent:
					var ext []*FileExtent
					ext, e = bt.FileExtents(r, 40, 1)
					if shortKey && e == nil && len(ext) == 0 {
						return
					}
				}
				if e == nil {
					t.Fatal("truncated record accepted")
				}
				if kind == FileSystemRecordTypeDirectoryEntry {
					if _, e = bt.DirectoryEntryRecordByUTF8Name(r, 40, "x", 1); e == nil {
						t.Fatal("invalid indexed record returned")
					}
				}
			})
		}
	}
	// Provider failure must propagate through both the root resolver and callers.
	broken := boundaryFSTree(nil)
	broken.IOHandle.BlockSize = 4096
	fault := errors.New("data provider failed")
	_, e := broken.AllRecordsForOID(boundaryFailedReader{fault}, 40)
	if !errors.Is(e, fault) {
		t.Fatalf("provider error hidden: %v", e)
	}
}

func TestFileSystemBTreeBoundaryNamesAndEviction(t *testing.T) {
	r := bytes.NewReader(nil)
	drec := func(parent, id uint64, name string) *BTreeEntry {
		key := append(boundaryFSKey(parent, FileSystemRecordTypeDirectoryEntry), make([]byte, 4)...)
		binary.LittleEndian.PutUint32(key[8:], uint32(len(name)+1)|CalculateNameHash([]byte(name), true)<<10)
		key = append(key, []byte(name)...)
		key = append(key, 0)
		value := make([]byte, 18)
		binary.LittleEndian.PutUint64(value, id)
		return &BTreeEntry{KeyData: key, ValueData: value}
	}
	valid := drec(2, 40, "file")
	missing := drec(2, 999, "missing")
	inode := &BTreeEntry{KeyData: boundaryFSKey(40, FileSystemRecordTypeInode), ValueData: make([]byte, 92)}
	bt := boundaryFSTree(map[uint64]*BTreeNode{100: boundaryFSNode(0, valid, missing, inode)})
	got, dir, e := bt.InodeByUTF16Name(r, 2, []uint16{'f', 'i', 'l', 'e'}, 1)
	if e != nil || got.Identifier != 40 || dir.Identifier != 40 {
		t.Fatalf("UTF16 inode lookup: %v", e)
	}
	got, _, e = bt.InodeByUTF16Path(r, 2, []uint16{'/', 'f', 'i', 'l', 'e', '/'}, 1)
	if e != nil || got.Identifier != 40 {
		t.Fatalf("UTF16 path lookup: %v", e)
	}
	for _, utf16 := range []bool{false, true} {
		if utf16 {
			_, _, e = bt.InodeByUTF16Name(r, 2, []uint16{'m', 'i', 's', 's', 'i', 'n', 'g'}, 1)
		} else {
			_, _, e = bt.InodeByUTF8Name(r, 2, "missing", 1)
		}
		if e == nil {
			t.Fatal("dangling directory record accepted")
		}
	}
	// Fill more than the documented cache capacity and prove an evicted index
	// is rebuilt from the source tree with the same record contents.
	for parent := uint64(100); parent < 140; parent++ {
		if _, e := bt.directoryIndex(r, parent); e != nil {
			t.Fatal(e)
		}
	}
	if len(bt.dirIndexes) != dirIndexCapacity {
		t.Fatalf("cache grew beyond bound: %d", len(bt.dirIndexes))
	}
	if _, exists := bt.dirIndexes[2]; exists {
		t.Fatal("old directory index was not evicted")
	}
	again, e := bt.DirectoryEntryRecordByUTF8Name(r, 2, "FILE", 1)
	if e != nil || again.Identifier != 40 {
		t.Fatalf("rebuilt index changed result: %v", e)
	}
	// A non-inode record with the requested identifier is not an inode.
	noInode := boundaryFSTree(map[uint64]*BTreeNode{100: boundaryFSNode(0, &BTreeEntry{KeyData: boundaryFSKey(40, FileSystemRecordTypeExtendedAttribute)})})
	if _, e := noInode.InodeByIdentifier(r, 40, 1); e == nil {
		t.Fatal("wrong record type accepted as inode")
	}
}

func TestFileSystemBTreeBoundaryEntryFailures(t *testing.T) {
	r := bytes.NewReader(nil)
	for _, node := range []*BTreeNode{
		boundaryFSNode(1),
		boundaryFSNode(1, &BTreeEntry{KeyData: boundaryFSKey(40, 3)}),
		boundaryFSNode(1, boundaryFSBranch(40, 119)),
		boundaryFSNode(0),
	} {
		if _, _, e := boundaryFSTree(map[uint64]*BTreeNode{100: node}).EntryByIdentifier(r, 40, 3, 1); e == nil {
			t.Fatal("corrupt or missing entry accepted")
		}
	}
	// Both failure sites in the last-child descent retain their errors too.
	for _, entry := range []*BTreeEntry{{KeyData: boundaryFSKey(10, 3)}, boundaryFSBranch(10, 119)} {
		bt := boundaryFSTree(map[uint64]*BTreeNode{100: boundaryFSNode(1, entry)})
		if _, e := bt.AllRecordsForOID(r, 90); e == nil {
			t.Fatal("invalid last child accepted")
		}
	}
}

// Inject a real ReaderAt failure beneath all block/tree wrappers.
type boundaryFailedReader struct{ err error }

func (r boundaryFailedReader) ReadAt([]byte, int64) (int, error) { return 0, r.err }
