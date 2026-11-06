package hfsplus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// TestWriteHardLinks round-trips several names for one file: the content must
// be stored once, and every name must read it back.
func TestWriteHardLinks(t *testing.T) {
	content := []byte("shared content, stored once\n")
	other := []byte("a different file\n")

	root := &Entry{Children: []*Entry{
		{Name: "a.txt", Mode: 0o644, Data: content, LinkGroup: 1},
		{Name: "b.txt", Mode: 0o644, Data: content, LinkGroup: 1},
		{Name: "c.txt", Mode: 0o644, Data: content, LinkGroup: 1},
		{Name: "plain.txt", Mode: 0o644, Data: other},
	}}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "LINKS", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}

	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		got, err := v.ReadFile(name)
		if err != nil {
			t.Errorf("ReadFile(%s): %v", name, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("%s = %q, want %q", name, got, content)
		}
		info, err := v.Stat(name)
		if err != nil {
			t.Errorf("Stat(%s): %v", name, err)
			continue
		}
		if info.Size() != int64(len(content)) {
			t.Errorf("%s: size = %d, want %d", name, info.Size(), len(content))
		}
	}

	if got, err := v.ReadFile("plain.txt"); err != nil || !bytes.Equal(got, other) {
		t.Errorf("plain.txt = %q, err=%v", got, err)
	}

	// The private metadata directory must not appear in a listing: it is
	// volume housekeeping, not a directory entry a caller should walk into.
	entries, err := v.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == metadataDirName {
			t.Error("the private metadata directory is visible in the root listing")
		}
	}
}

// TestWriteHardLinksStoreContentOnce is the point of the feature: three names
// for a megabyte must cost a megabyte, not three.
func TestWriteHardLinksStoreContentOnce(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789ABCDEF"), 64*1024) // 1 MiB

	linked := &Entry{Children: []*Entry{
		{Name: "a.bin", Mode: 0o644, Data: big, LinkGroup: 7},
		{Name: "b.bin", Mode: 0o644, Data: big, LinkGroup: 7},
		{Name: "c.bin", Mode: 0o644, Data: big, LinkGroup: 7},
	}}
	copies := &Entry{Children: []*Entry{
		{Name: "a.bin", Mode: 0o644, Data: big},
		{Name: "b.bin", Mode: 0o644, Data: big},
		{Name: "c.bin", Mode: 0o644, Data: big},
	}}

	build := func(root *Entry) int {
		w := &memWriterAt{}
		if err := CreateImage(w, 0, "SIZE", root, nil); err != nil {
			t.Fatalf("CreateImage: %v", err)
		}
		return len(w.b)
	}

	linkedSize, copiesSize := build(linked), build(copies)
	if linkedSize >= copiesSize-int(len(big)) {
		t.Errorf("linked image is %d bytes and the copied one %d; the content was not shared",
			linkedSize, copiesSize)
	}
}

// TestWriteHardLinkAttributes checks that attributes follow the content rather
// than a name. A reader resolving any name lands on the indirect node, so that
// is where they have to live.
func TestWriteHardLinkAttributes(t *testing.T) {
	attrs := map[string][]byte{"com.example.test": []byte("value42")}
	root := &Entry{Children: []*Entry{
		{Name: "a.txt", Mode: 0o644, Data: []byte("x\n"), Xattrs: attrs, LinkGroup: 3},
		{Name: "b.txt", Mode: 0o644, Data: []byte("x\n"), Xattrs: attrs, LinkGroup: 3},
	}}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "LINKATTR", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, name := range []string{"a.txt", "b.txt"} {
		got, err := v.Xattrs(name)
		if err != nil {
			t.Errorf("Xattrs(%s): %v", name, err)
			continue
		}
		if string(got["com.example.test"]) != "value42" {
			t.Errorf("%s attributes = %v", name, got)
		}
	}
}

// TestWriteSingleLinkGroupIsNotALink checks a group of one stays an ordinary
// file: a walker only assigns a group when it saw several names, but a caller
// building a tree by hand might not.
func TestWriteSingleLinkGroupIsNotALink(t *testing.T) {
	root := &Entry{Children: []*Entry{
		{Name: "only.txt", Mode: 0o644, Data: []byte("alone\n"), LinkGroup: 9},
	}}
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "ONE", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, err := v.ReadFile("only.txt"); err != nil || string(got) != "alone\n" {
		t.Errorf("only.txt = %q, err=%v", got, err)
	}
	entries, err := v.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("root has %d entries, want 1: a lone group should not create a private directory", len(entries))
	}
}

// TestWriteHardLinkChain covers what this package's own reader never looks at
// and macOS insists on.
//
// The names for one file form a doubly-linked chain: each link record carries
// its neighbours' catalog ids where an ordinary record keeps its owner and
// group, the indirect node points at the head of the chain in its reserved1
// field, and all of them carry kHFSHasLinkChainMask. Without it fsck_hfs says
// "found N pre-Leopard file inodes" and calls the volume corrupt, and macOS
// reads every linked name as an empty file — while our reader, which resolves a
// link through the special field alone, is perfectly happy. That gap is why the
// tests above passed against a volume no other tool would accept.
func TestWriteHardLinkChain(t *testing.T) {
	root := &Entry{Children: []*Entry{
		{Name: "a.txt", Mode: 0o644, Data: []byte("shared\n"), LinkGroup: 1},
		{Name: "b.txt", Mode: 0o644, Data: []byte("shared\n"), LinkGroup: 1},
		{Name: "c.txt", Mode: 0o644, Data: []byte("shared\n"), LinkGroup: 1},
	}}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "CHAIN", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The raw records, not what lookup returns: lookup resolves a link to its
	// indirect node, so it can never show what the link record itself holds.
	// That is exactly the blind spot this test exists to cover.
	files, folders := rawCatalogRecords(t, v)

	names := []string{"a.txt", "b.txt", "c.txt"}
	links := make([]*HFSPlusCatalogFile, len(names))
	for i, name := range names {
		rec, ok := files[name]
		if !ok {
			t.Fatalf("no catalog record for %s", name)
		}
		links[i] = rec
		if rec.Flags&HFSHasLinkChainMask == 0 {
			t.Errorf("%s: kHFSHasLinkChainMask not set (flags %#06x)", name, rec.Flags)
		}
		if rec.UserInfo.FileType != HardLinkFileType {
			t.Errorf("%s: file type = %#08x, want hlnk (%#08x)", name, rec.UserInfo.FileType, HardLinkFileType)
		}
	}

	// Every name points at the same indirect node.
	inodeID := links[0].BSDInfo.Special
	for i, name := range names {
		if links[i].BSDInfo.Special != inodeID {
			t.Errorf("%s points at inode %d, want %d", name, links[i].BSDInfo.Special, inodeID)
		}
	}

	// The chain: first has no previous, last has no next, and each pair agrees
	// in both directions.
	if links[0].BSDInfo.OwnerID != 0 {
		t.Errorf("the first link has a previous id %d, want 0", links[0].BSDInfo.OwnerID)
	}
	if last := links[len(links)-1]; last.BSDInfo.GroupID != 0 {
		t.Errorf("the last link has a next id %d, want 0", last.BSDInfo.GroupID)
	}
	for i := 0; i < len(links)-1; i++ {
		next, prev := links[i].BSDInfo.GroupID, links[i+1].BSDInfo.OwnerID
		if next != uint32(links[i+1].FileID) {
			t.Errorf("%s: next = %d, want %d", names[i], next, links[i+1].FileID)
		}
		if prev != uint32(links[i].FileID) {
			t.Errorf("%s: previous = %d, want %d", names[i+1], prev, links[i].FileID)
		}
	}

	// Every link record repeats the private directory's creation date, which is
	// the check fsck_hfs spells out: "Hard Link catalog entry N has bad time".
	privateDir, ok := folders[metadataDirName]
	if !ok {
		t.Fatal("no catalog record for the private metadata directory")
	}
	for i, name := range names {
		if links[i].CreateDate != privateDir.CreateDate {
			t.Errorf("%s: create date = %d, want the private directory's %d",
				name, links[i].CreateDate, privateDir.CreateDate)
		}
	}

	// The indirect node names the head of the chain and carries the flag too.
	inode, ok := files[fmt.Sprintf("iNode%d", inodeID)]
	if !ok {
		t.Fatalf("no catalog record for iNode%d", inodeID)
	}
	if inode.Flags&HFSHasLinkChainMask == 0 {
		t.Errorf("the indirect node lacks kHFSHasLinkChainMask (flags %#06x); "+
			"fsck_hfs calls that a pre-Leopard file inode", inode.Flags)
	}
	if inode.Reserved1 != uint32(links[0].FileID) {
		t.Errorf("the indirect node's first link = %d, want %d", inode.Reserved1, links[0].FileID)
	}
	if inode.BSDInfo.Special != uint32(len(names)) {
		t.Errorf("the indirect node's link count = %d, want %d", inode.BSDInfo.Special, len(names))
	}
}

// rawCatalogRecords returns every file and folder record by name, straight from
// the catalog B-tree.
func rawCatalogRecords(t *testing.T, v *Volume) (map[string]*HFSPlusCatalogFile, map[string]*HFSPlusCatalogFolder) {
	t.Helper()
	files := map[string]*HFSPlusCatalogFile{}
	folders := map[string]*HFSPlusCatalogFolder{}

	err := v.catalogTree.walkLeaves(func(rec leafRecord) error {
		_, name, err := parseCatalogKey(rec.key)
		if err != nil || len(rec.data) < 2 {
			return nil
		}
		switch RecordType(binary.BigEndian.Uint16(rec.data)) {
		case HFSPlusFileRecord:
			var f HFSPlusCatalogFile
			if err := binary.Read(bytes.NewReader(rec.data), binary.BigEndian, &f); err == nil {
				files[name] = &f
			}
		case HFSPlusFolderRecord:
			var f HFSPlusCatalogFolder
			if err := binary.Read(bytes.NewReader(rec.data), binary.BigEndian, &f); err == nil {
				folders[name] = &f
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the catalog: %v", err)
	}
	return files, folders
}
