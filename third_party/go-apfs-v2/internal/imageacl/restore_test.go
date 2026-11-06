package imageacl

import (
	"bytes"
	"errors"
	"io/fs"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

type entry struct {
	node Node[*entry]
	fail error
}

func apply(root, target *entry, update appledouble.ACLUpdate) (aclmeta.ACLRestoreResult, error) {
	return Restore(root, target, update, func(e *entry, _ bool) (Node[*entry], error) { return e.node, e.fail }, func(e *entry, attrs map[string][]byte) { e.node.Xattrs = attrs })
}
func replacement() appledouble.ACLUpdate {
	return appledouble.ACLUpdate{ACL: &appledouble.ACL{Flags: 1 << 17, Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 2}}}}
}
func TestImageACLRestoreValidation(t *testing.T) {
	for _, u := range []appledouble.ACLUpdate{{}, {Invalid: true}} {
		if r, e := apply(nil, nil, u); e != nil || r.Applied || r.Attempts != 0 {
			t.Fatal(r, e)
		}
	}
	for _, u := range []appledouble.ACLUpdate{{ACL: &appledouble.ACL{}, Invalid: true}, {ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}}} {
		if _, e := apply(nil, nil, u); !errors.Is(e, appledouble.ErrFileSecurity) {
			t.Fatal(e)
		}
	}
	u := replacement()
	root := &entry{node: Node[*entry]{Mode: 040755}}
	target := &entry{node: Node[*entry]{Mode: 0100644}}
	for _, pair := range [][2]*entry{{nil, target}, {root, nil}} {
		if _, e := apply(pair[0], pair[1], u); !errors.Is(e, fs.ErrInvalid) {
			t.Fatal(e)
		}
	}
	if _, e := apply(root, target, u); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	for _, children := range [][]*entry{{nil}, {root}, {target, target}} {
		root.node.Children = children
		if _, e := apply(root, target, u); !errors.Is(e, fs.ErrInvalid) {
			t.Fatal(e)
		}
	}
	root.node.Children = []*entry{target}
	sentinel := errors.New("metadata capture failed")
	target.fail = sentinel
	if _, e := apply(root, target, u); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if target.node.Xattrs != nil || root.node.Xattrs != nil {
		t.Fatal("failed validation changed tree")
	}
}
func TestImageACLRestoreAliases(t *testing.T) {
	for _, conflict := range []string{"none", "owner", "group", "mode", "presence", "bytes"} {
		t.Run(conflict, func(t *testing.T) {
			raw, e := (&appledouble.FileSecurity{OwnerUUID: [16]byte{1}, GroupUUID: [16]byte{2}}).MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			a := &entry{node: Node[*entry]{Mode: 0107000, UID: 42, GID: 43, LinkGroup: 7, Xattrs: map[string][]byte{hostdata.SecurityName: raw, "user.keep": {3}}}}
			b := &entry{node: a.node}
			b.node.Xattrs = map[string][]byte{hostdata.SecurityName: bytes.Clone(raw), "user.other": {4}}
			switch conflict {
			case "owner":
				b.node.UID++
			case "group":
				b.node.GID++
			case "mode":
				b.node.Mode++
			case "presence":
				delete(b.node.Xattrs, hostdata.SecurityName)
			case "bytes":
				b.node.Xattrs[hostdata.SecurityName][4]++
			}
			root := &entry{node: Node[*entry]{Mode: 040755, Children: []*entry{a, b}}}
			oldA, oldB := a.node.Xattrs, b.node.Xattrs
			beforeA, beforeB := bytes.Clone(oldA[hostdata.SecurityName]), bytes.Clone(oldB[hostdata.SecurityName])
			r, err := apply(root, b, replacement())
			if conflict != "none" {
				if !errors.Is(err, fs.ErrInvalid) || r.Applied {
					t.Fatal(r, err)
				}
			} else {
				if err != nil || !r.Applied || r.Attempts != 1 || r.Retried {
					t.Fatal(r, err)
				}
				for _, v := range []*entry{a, b} {
					s, err := appledouble.ParseFileSecurity(v.node.Xattrs[hostdata.SecurityName])
					if err != nil || s.OwnerUUID[0] != 1 || s.GroupUUID[0] != 2 || len(s.ACL.Entries) != 1 || s.ACL.Flags != 1<<17 {
						t.Fatal(s, err)
					}
				}
				a.node.Xattrs[hostdata.SecurityName][4] = 99
				if b.node.Xattrs[hostdata.SecurityName][4] != 1 {
					t.Fatal("aliases share new security storage")
				}
			}
			if !bytes.Equal(oldA[hostdata.SecurityName], beforeA) || !bytes.Equal(oldB[hostdata.SecurityName], beforeB) {
				t.Fatal("old maps changed")
			}
			if a.node.UID != 42 || a.node.GID != 43 || a.node.Mode != 0107000 || a.node.Xattrs["user.keep"][0] != 3 || b.node.Xattrs["user.other"][0] != 4 {
				t.Fatal("unrelated metadata changed")
			}
		})
	}
	// Group IDs on directories or symlinks do not create regular-file aliases.
	a := &entry{node: Node[*entry]{Mode: 0100644, LinkGroup: 7}}
	b := &entry{node: Node[*entry]{Mode: 0120755, LinkGroup: 7}}
	dir := &entry{node: Node[*entry]{Mode: 040755, LinkGroup: 7, Children: []*entry{a, b}}}
	if _, e := apply(dir, a, replacement()); e != nil {
		t.Fatal(e)
	}
	if b.node.Xattrs != nil || dir.node.Xattrs != nil {
		t.Fatal("non-file alias changed")
	}
}
func TestImageACLRestoreRecords(t *testing.T) {
	valid, e := (&appledouble.FileSecurity{OwnerUUID: [16]byte{1}, ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1}}}}).MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{nil, {}, {1}, make([]byte, 44), append(bytes.Clone(valid), make([]byte, 24)...), valid} {
		root := &entry{node: Node[*entry]{Mode: 040000, UID: 0, GID: 0, Xattrs: map[string][]byte{hostdata.SecurityName: raw}}}
		before := bytes.Clone(raw)
		u := replacement()
		snapshot := *u.ACL
		snapshot.Entries = append([]appledouble.ACLEntry(nil), u.ACL.Entries...)
		r, e := apply(root, root, u)
		if e != nil || !r.Applied {
			t.Fatal(r, e)
		}
		if !bytes.Equal(raw, before) || !reflect.DeepEqual(*u.ACL, snapshot) {
			t.Fatal("input mutated")
		}
		if len(root.node.Xattrs[hostdata.SecurityName]) != 68 {
			t.Fatal("noncanonical output")
		}
	}
	backend := &restorer{}
	if e := backend.ClearSourceSecurity(); e != nil {
		t.Fatal(e)
	}
	if e := backend.WriteACL(aclmeta.ACLMetadata{Security: &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}}}); !errors.Is(e, appledouble.ErrFileSecurity) {
		t.Fatal(e)
	}
}

func FuzzImageACLRestore(f *testing.F) {
	f.Add([]byte{}, uint8(0))
	f.Add(make([]byte, 44), uint8(7))
	f.Add([]byte{1, 2, 3}, uint8(2))
	f.Fuzz(func(t *testing.T, raw []byte, shape uint8) {
		if len(raw) > 4096 {
			return
		}
		original := bytes.Clone(raw)
		target := &entry{node: Node[*entry]{Mode: 0107000, LinkGroup: 1, Xattrs: map[string][]byte{hostdata.SecurityName: raw}}}
		root := &entry{node: Node[*entry]{Mode: 040755, Children: []*entry{target}}}
		switch shape % 4 {
		case 1:
			root.node.Children = append(root.node.Children, root)
		case 2:
			root.node.Children = append(root.node.Children, target)
		case 3:
			root.node.Children = append(root.node.Children, nil)
		}
		r, err := apply(root, target, replacement())
		if !bytes.Equal(raw, original) || target.node.Mode != 0107000 {
			t.Fatal("input or mode changed")
		}
		if shape%4 != 0 {
			if err == nil || r.Applied {
				t.Fatal("invalid graph accepted")
			}
			return
		}
		if err != nil || !r.Applied || r.Attempts != 1 {
			t.Fatal(r, err)
		}
		if s, e := appledouble.ParseFileSecurity(target.node.Xattrs[hostdata.SecurityName]); e != nil || len(s.ACL.Entries) != 1 {
			t.Fatal(s, e)
		}
	})
}
