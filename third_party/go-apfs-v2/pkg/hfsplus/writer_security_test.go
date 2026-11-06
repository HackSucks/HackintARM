package hfsplus

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestWriteSecurityFlags(t *testing.T) {
	acl := &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{0x11}, Flags: 1, Rights: 1 << 12}}}
	security, e := acl.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	for _, ci := range []bool{false, true} {
		for _, tc := range []struct {
			name  string
			attrs map[string][]byte
			flags CatalogFlags
		}{
			{"absent", nil, 0}, {"ordinary", map[string][]byte{"com.example.test": {1}}, HFSHasAttributesMask},
			{"security", map[string][]byte{"com.apple.system.Security": security}, HFSHasAttributesMask | HFSHasSecurityMask},
			{"empty-security", map[string][]byte{"com.apple.system.Security": {}}, HFSHasAttributesMask | HFSHasSecurityMask},
			{"nil-security", map[string][]byte{"com.apple.system.Security": nil}, HFSHasAttributesMask | HFSHasSecurityMask},
			{"wrong-case", map[string][]byte{"com.apple.system.security": security}, HFSHasAttributesMask},
			{"mixed", map[string][]byte{"a.before": {1}, "com.apple.system.Security": security, "z.after": {2}}, HFSHasAttributesMask | HFSHasSecurityMask},
		} {
			t.Run(fmt.Sprintf("case-insensitive-%t/%s", ci, tc.name), func(t *testing.T) {
				root := &Entry{Mode: os.ModeDir | 0755, Xattrs: tc.attrs, Children: []*Entry{
					{Name: "file", Mode: 0644, Data: []byte("payload"), Xattrs: tc.attrs},
					{Name: "directory", Mode: os.ModeDir | 0755, Xattrs: tc.attrs},
					{Name: "symlink", Mode: os.ModeSymlink | 0755, Data: []byte("file"), Xattrs: tc.attrs},
					{Name: "hard-a", Mode: 0644, Data: []byte("linked"), Xattrs: tc.attrs, LinkGroup: 1},
					{Name: "hard-b", Mode: 0644, Data: []byte("linked"), Xattrs: tc.attrs, LinkGroup: 1},
				}}
				w := &memWriterAt{}
				if e := CreateImage(w, 0, "SECURITY", root, &CreateOptions{CaseInsensitive: ci}); e != nil {
					t.Fatal(e)
				}
				v, e := New(bytes.NewReader(w.b))
				if e != nil {
					t.Fatal(e)
				}
				for _, name := range []string{".", "file", "directory", "symlink", "hard-a", "hard-b"} {
					entry, e := v.lookup(name)
					if e != nil {
						t.Fatal(e)
					}
					var flags CatalogFlags
					if entry.isDir {
						flags = entry.folder.Flags
					} else {
						flags = entry.file.Flags
					}
					if got := flags & (HFSHasAttributesMask | HFSHasSecurityMask); got != tc.flags {
						t.Fatalf("%s flags %#x want %#x", name, got, tc.flags)
					}
					attrs, e := v.Xattrs(name)
					if e != nil {
						t.Fatal(e)
					}
					if len(attrs) != len(tc.attrs) {
						t.Fatal("attribute count changed")
					}
					for key, want := range tc.attrs {
						got, present := attrs[key]
						if !present || !bytes.Equal(got, want) {
							t.Fatal("attribute loss", name, key)
						}
					}
				}
				files, _ := rawCatalogRecords(t, v)
				for _, name := range []string{"hard-a", "hard-b"} {
					if files[name].Flags&(HFSHasAttributesMask|HFSHasSecurityMask) != 0 {
						t.Fatal("hard-link name claims indirect inode attributes")
					}
				}
				for name, want := range map[string]string{"file": "payload", "hard-a": "linked", "hard-b": "linked"} {
					got, e := v.ReadFile(name)
					if e != nil || string(got) != want {
						t.Fatal("data changed", name, e)
					}
				}
				target, e := v.Readlink("symlink")
				if e != nil || target != "file" {
					t.Fatal("symlink changed", e)
				}
			})
		}
	}
}
