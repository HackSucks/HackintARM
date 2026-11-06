package hfsplus

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestImageFinderInfoCatalog(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		for _, kind := range []string{"file", "directory", "symlink", "hardlink", "root"} {
			for _, form := range []string{"value", "zero", "hidden", "private", "explicit-clear"} {
				t.Run(kind+"/"+form+map[bool]string{false: "/hfsplus", true: "/hfsx"}[sensitive], func(t *testing.T) {
					raw := make([]byte, 32)
					switch form {
					case "value":
						for i := range raw {
							raw[i] = byte(i + 1)
						}
					case "hidden", "explicit-clear":
						raw[8] = 0x40
					case "private":
						for i := 16; i < 24; i++ {
							raw[i] = 0xaa
						}
						for i := 28; i < 32; i++ {
							raw[i] = 0xbb
						}
					}
					want := bytes.Clone(raw)
					clear(want[16:24])
					clear(want[28:32])
					if kind == "symlink" {
						clear(want[:8])
					}
					if form == "explicit-clear" {
						want[8] &^= 0x40
					}
					child := &Entry{Name: "item", Mode: 0644, Data: []byte("payload"), Xattrs: map[string][]byte{finderInfoName: raw}}
					if form == "explicit-clear" {
						zero := uint32(0)
						child.BSDFlags = &zero
					}
					if kind == "directory" || kind == "root" {
						child.Mode = os.ModeDir | 0755
						child.Data = nil
					}
					if kind == "symlink" {
						child.Mode = os.ModeSymlink | 0755
						child.Data = []byte("target")
					}
					root := &Entry{Mode: os.ModeDir | 0755, Children: []*Entry{child}}
					name := "item"
					if kind == "root" {
						root = child
						name = "."
					}
					if kind == "hardlink" {
						child.LinkGroup = 1
						alias := *child
						alias.Name = "alias"
						root.Children = append(root.Children, &alias)
					}
					output := &memWriterAt{}
					if e := CreateImage(output, 32<<20, "FINDER", root, &CreateOptions{CaseInsensitive: !sensitive}); e != nil {
						t.Fatal(e)
					}
					v, e := New(bytes.NewReader(output.b))
					if e != nil {
						t.Fatal(e)
					}
					attrs, e := v.Xattrs(name)
					if e != nil {
						t.Fatal(e)
					}
					if bytes.Equal(want, make([]byte, 32)) {
						if _, ok := attrs[finderInfoName]; ok {
							t.Fatal("zero FinderInfo visible")
						}
					} else if !bytes.Equal(attrs[finderInfoName], want) {
						t.Fatalf("%x != %x", attrs[finderInfoName], want)
					}
					entry, e := v.lookup(name)
					if e != nil {
						t.Fatal(e)
					}
					id, _ := entryFileID(entry)
					if _, ok := v.attributes[attrKey{id, finderInfoName}]; ok {
						t.Fatal("FinderInfo written into attributes tree")
					}
					if kind == "hardlink" {
						other, e := v.Xattrs("alias")
						if e != nil || !bytes.Equal(other[finderInfoName], attrs[finderInfoName]) {
							t.Fatal("alias FinderInfo", e)
						}
					}
					flags, e := v.BSDFlags(name)
					if e != nil {
						t.Fatal(e)
					}
					if (flags&0x8000 != 0) != (want[8]&0x40 != 0) {
						t.Fatal("invisible flag disagrees")
					}
					if !bytes.Equal(raw, child.Xattrs[finderInfoName]) {
						t.Fatal("mutated caller input")
					}
				})
			}
		}
	}
}

func TestImageFinderInfoInvalidAndConflictingStorage(t *testing.T) {
	for _, b := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33), append([]byte("hlnk"), make([]byte, 28)...)} {
		if e := CreateImage(&memWriterAt{}, 32<<20, "BAD", &Entry{Xattrs: map[string][]byte{finderInfoName: b}}, nil); e == nil {
			t.Fatal("accepted invalid FinderInfo")
		}
	}
	if e := validateEntry(&Entry{Xattrs: map[string][]byte{"invalid\xff": {}}}, "."); e == nil {
		t.Fatal("accepted invalid UTF-8")
	}
	e := &entry{file: &HFSPlusCatalogFile{BSDInfo: BSDInfo{FileMode: 0100644}}}
	if addCatalogFinderInfo(map[string][]byte{finderInfoName: make([]byte, 32)}, e) == nil {
		t.Fatal("noncanonical storage ignored")
	}
	raw := make([]byte, 32)
	copy(raw, []byte("TEXTTEST"))
	e.file.UserInfo.FileType = binary.BigEndian.Uint32(raw[:4])
	e.file.UserInfo.FileCreator = binary.BigEndian.Uint32(raw[4:8])
	attrs := map[string][]byte{finderInfoName: bytes.Clone(raw)}
	if err := addCatalogFinderInfo(attrs, e); err != nil {
		t.Fatal(err)
	}
	attrs[finderInfoName][0] ^= 1
	if err := addCatalogFinderInfo(attrs, e); err == nil {
		t.Fatal("disagreeing duplicate accepted")
	}
	v := &Volume{root: &entry{isDir: true, folder: &HFSPlusCatalogFolder{FolderID: 2}}, attributes: map[attrKey]*attrRecord{{2, finderInfoName}: {inline: raw}}, attrNames: map[CatalogNodeID][]string{2: {finderInfoName}}}
	if _, err := v.Xattrs("."); err == nil {
		t.Fatal("source API hides conflicting reserved storage")
	}
}
