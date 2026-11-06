package hfsplus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func boundaryTree(t *testing.T, records []btRecord) *btree {
	t.Helper()
	built := buildBTree(512, records, HFSBinaryCompare, 0, 266, 0)
	var data []byte
	for _, n := range built.nodes {
		data = append(data, n...)
	}
	fork, err := newForkReader(bytes.NewReader(data), 512, uint64(len(data)), []ExtentDescriptor{{BlockCount: uint32(len(data) / 512)}})
	if err != nil {
		t.Fatal(err)
	}
	tree, err := openBTree(fork)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func overflowBoundaryRecord(file CatalogNodeID, start uint32, physical uint32) btRecord {
	key := make([]byte, 12)
	binary.BigEndian.PutUint16(key, 10)
	binary.BigEndian.PutUint32(key[4:], uint32(file))
	binary.BigEndian.PutUint32(key[8:], start)
	payload := make([]byte, 64)
	binary.BigEndian.PutUint32(payload, physical)
	binary.BigEndian.PutUint32(payload[4:], 1)
	return btRecord{key: key, payload: payload}
}

func TestVolumeBoundaryOverflow(t *testing.T) {
	data := bytes.Repeat([]byte{0}, 512*5)
	for i := 0; i < 5; i++ {
		for j := i * 512; j < (i+1)*512; j++ {
			data[j] = byte('a' + i)
		}
	}
	v := &Volume{dev: bytes.NewReader(data), blockSize: 512, extentsTree: boundaryTree(t, []btRecord{
		overflowBoundaryRecord(40, 2, 4), // intentionally out of logical order
		overflowBoundaryRecord(40, 0, 0), // overlaps inline coverage, never appended
		overflowBoundaryRecord(40, 1, 3),
	})}
	fork := ForkData{LogicalSize: 1536, TotalBlocks: 3, Extents: ExtentRecord{{StartBlock: 1, BlockCount: 1}}}
	r, err := v.forkReaderFor(40, forkTypeData, fork)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1536)
	if _, err = r.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte{'b'}, 512), bytes.Repeat([]byte{'d'}, 512)...)
	want = append(want, bytes.Repeat([]byte{'e'}, 512)...)
	if !bytes.Equal(got, want) {
		t.Fatal("overflow logical order changed payload")
	}
	// The successfully loaded cache is reusable even after its provider disappears.
	v.extentsTree = nil
	if _, err = v.forkReaderFor(40, forkTypeData, fork); err != nil {
		t.Fatal(err)
	}
	fork.TotalBlocks = 4
	if _, err = v.forkReaderFor(40, forkTypeData, fork); err == nil || !strings.Contains(err.Error(), "3 of 4") {
		t.Fatalf("missing extent accepted: %v", err)
	}
	absent := &Volume{dev: bytes.NewReader(data), blockSize: 512}
	if _, err = absent.forkReaderFor(40, forkTypeData, fork); err == nil {
		t.Fatal("missing overflow tree accepted")
	}
	if _, err = absent.forkReaderFor(40, forkTypeData, ForkData{LogicalSize: 1 << 63}); err == nil {
		t.Fatal("unrepresentable fork accepted")
	}
}

func TestVolumeBoundaryMalformedOverflow(t *testing.T) {
	for _, kind := range []string{"key", "value", "provider"} {
		t.Run(kind, func(t *testing.T) {
			record := overflowBoundaryRecord(40, 1, 3)
			switch kind {
			case "key":
				record.key = []byte{0, 2, 0, 0}
			case "value":
				record.payload = record.payload[:8]
			}
			tree := boundaryTree(t, []btRecord{record})
			if kind == "provider" {
				tree.fork.dev = bytes.NewReader(nil)
			}
			v := &Volume{dev: bytes.NewReader(nil), blockSize: 512, extentsTree: tree}
			fork := ForkData{LogicalSize: 1024, TotalBlocks: 2, Extents: ExtentRecord{{BlockCount: 1}}}
			if _, err := v.forkReaderFor(40, forkTypeData, fork); err == nil {
				t.Fatal("malformed overflow accepted")
			}
			// A failed load must not publish a partially populated success cache.
			if err := v.loadOverflowExtents(); err == nil {
				t.Fatal("failed overflow load was cached as success")
			}
		})
	}
}

func TestVolumeBoundaryCatalog(t *testing.T) {
	root := btRecord{key: encodeCatalogKey(HFSRootParentID, "root"), payload: marshalBE(HFSPlusCatalogFolder{RecordType: HFSPlusFolderRecord, FolderID: HFSRootFolderID})}
	for _, tc := range []struct {
		name    string
		records []btRecord
	}{
		{"key", []btRecord{{key: []byte{0, 2, 0, 0}, payload: []byte{0, 1}}}},
		{"record", []btRecord{{key: encodeCatalogKey(2, "short"), payload: []byte{0}}}},
		{"folder", []btRecord{{key: encodeCatalogKey(2, "short"), payload: []byte{0, 1}}}},
		{"file", []btRecord{{key: encodeCatalogKey(2, "short"), payload: []byte{0, 2}}}},
		{"no-root", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &Volume{catalogTree: boundaryTree(t, tc.records)}
			if err := v.loadCatalog(); err == nil {
				t.Fatal("malformed catalog accepted")
			}
		})
	}
	v := &Volume{catalogTree: boundaryTree(t, []btRecord{root,
		{key: encodeCatalogKey(999, "orphan-dir"), payload: marshalBE(HFSPlusCatalogFolder{RecordType: HFSPlusFolderRecord, FolderID: 88})},
		{key: encodeCatalogKey(999, "orphan-file"), payload: marshalBE(HFSPlusCatalogFile{RecordType: HFSPlusFileRecord, FileID: 89})},
	})}
	if err := v.loadCatalog(); err != nil {
		t.Fatal(err)
	}
	if len(v.root.children) != 0 || v.Name() != "root" {
		t.Fatal("orphan exposed under root")
	}
	for _, key := range [][]byte{nil, {0, 0, 0, 2, 0, 2, 0, 65}} {
		if _, _, err := parseCatalogKey(key); err == nil {
			t.Fatal("truncated catalog key accepted")
		}
	}
}

func TestVolumeBoundaryLinksAndForks(t *testing.T) {
	inode := &HFSPlusCatalogFile{FileID: 70}
	indirect := func(id uint32) *HFSPlusCatalogFile {
		f := &HFSPlusCatalogFile{}
		f.UserInfo.FileType = HardLinkFileType
		f.UserInfo.FileCreator = HFSPlusCreator
		f.BSDInfo.Special = id
		return f
	}
	good := &entry{name: "good", file: indirect(7)}
	broken := &entry{name: "broken", file: indirect(8)}
	dirlink := &entry{name: "dirlink", file: &HFSPlusCatalogFile{}}
	dirlink.file.UserInfo.FileType = DirLinkFileType
	dirlink.file.UserInfo.FileCreator = DirLinkCreator
	private := &entry{name: metadataDirName, isDir: true, children: []*entry{
		{name: "empty"}, {name: "other", file: inode}, {name: "iNodeNaN", file: inode}, {name: "iNode7", file: inode},
	}}
	v := &Volume{root: &entry{isDir: true, children: []*entry{private, good, broken, dirlink, {name: "empty"}}}}
	v.resolveHardLinks()
	if good.file != inode || broken.brokenLink != 8 || !dirlink.isDirLink {
		t.Fatal("hardlink resolution lost classification")
	}
	for _, e := range []*entry{{isDir: true}, dirlink, broken, {}} {
		if _, err := v.dataForkReader(e); err == nil {
			t.Fatal("invalid fork entry accepted")
		}
	}
	if _, err := v.lookup("good/child"); err == nil {
		t.Fatal("file traversed as directory")
	}
	v.root.children = []*entry{{name: "x:y", file: inode}}
	if e, err := v.lookup("x:y"); err != nil || e != v.root.children[0] {
		t.Fatalf("legacy colon lookup failed: %v", err)
	}
	if v.UUID() != "" {
		t.Fatal("invented volume UUID")
	}
	for _, e := range []*entry{{isDir: true}, {file: &HFSPlusCatalogFile{}}} {
		if _, err := v.readlink(e); err == nil {
			t.Fatal("nonsymlink read accepted")
		}
	}
	link := &entry{file: &HFSPlusCatalogFile{BSDInfo: BSDInfo{FileMode: sIFLNK}}}
	v.blockSize = 512
	v.dev = bytes.NewReader(nil)
	if s, err := v.readlink(link); err != nil || s != "" {
		t.Fatalf("empty link: %q %v", s, err)
	}
	link.brokenLink = 9
	if _, err := v.readlink(link); err == nil {
		t.Fatal("broken link payload accepted")
	}
	link.brokenLink = 0
	link.file.DataFork = ForkData{LogicalSize: 3, TotalBlocks: 1, Extents: ExtentRecord{{BlockCount: 1}}}
	if _, err := v.readlink(link); !errors.Is(err, io.EOF) {
		t.Fatalf("missing link payload lost error: %v", err)
	}
}

func TestVolumeBoundaryHeaders(t *testing.T) {
	if _, err := New(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("short header: %v", err)
	}
	for _, kind := range []string{"signature", "block-size", "extent-size", "extent-header", "catalog-extents", "catalog-header", "catalog-records"} {
		t.Run(kind, func(t *testing.T) {
			hdr := VolumeHeader{Signature: HFSPlusSigWord, Version: HFSPlusVersion, BlockSize: 512}
			switch kind {
			case "signature":
				hdr.Signature = 0
			case "block-size":
				hdr.BlockSize = 513
			case "extent-size":
				hdr.ExtentsFile.LogicalSize = 1 << 63
			case "extent-header":
				hdr.ExtentsFile.LogicalSize = 512
				hdr.ExtentsFile.Extents[0] = ExtentDescriptor{BlockCount: 1}
			case "catalog-extents":
				hdr.CatalogFile.TotalBlocks = 1
			case "catalog-header":
				hdr.CatalogFile.LogicalSize = 512
				hdr.CatalogFile.Extents[0] = ExtentDescriptor{BlockCount: 1}
			case "catalog-records":
				tree := buildBTree(512, nil, HFSBinaryCompare, 0, 266, 0)
				var data []byte
				for _, n := range tree.nodes {
					data = append(data, n...)
				}
				hdr.CatalogFile = ForkData{LogicalSize: uint64(len(data)), TotalBlocks: uint32(len(tree.nodes)), Extents: ExtentRecord{{StartBlock: 4, BlockCount: uint32(len(tree.nodes))}}}
				device := make([]byte, 2048)
				copy(device[1024:], marshalBE(hdr))
				device = append(device, data...)
				if _, err := New(bytes.NewReader(device)); err == nil || !strings.Contains(err.Error(), "no root") {
					t.Fatalf("rootless catalog: %v", err)
				}
				return
			}
			device := make([]byte, 1536)
			copy(device[1024:], marshalBE(hdr))
			if _, err := New(bytes.NewReader(device)); err == nil {
				t.Fatal("invalid header accepted")
			}
		})
	}
}
