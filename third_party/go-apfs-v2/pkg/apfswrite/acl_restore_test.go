package apfswrite

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestImageACLRestoreTreeValidation(t *testing.T) {
	update := appledouble.ACLUpdate{ACL: &appledouble.ACL{}}
	for _, root := range []*Entry{{Mode: os.ModeSymlink}, {Mode: os.ModeDevice}, {Mode: os.ModeDir, Children: []*Entry{{Name: "device", Mode: os.ModeNamedPipe}}}, {Mode: os.ModeDir, Children: []*Entry{{Name: "file", Mode: 0644, Children: []*Entry{{Name: "child"}}}}}} {
		if r, e := root.RestoreACL(root, update); !errors.Is(e, fs.ErrInvalid) || r.Applied || root.Xattrs != nil {
			t.Fatal(r, e)
		}
	}
	var root *Entry
	if r, e := root.RestoreACL(nil, appledouble.ACLUpdate{}); e != nil || r.Applied {
		t.Fatal(r, e)
	}
	// A target can be selected through an alias nested in another directory.
	first := &Entry{Name: "first", Mode: 0, ModeExplicit: true, LinkGroup: 3, UID: 42, GID: 43}
	second := *first
	second.Name = "second"
	root = &Entry{Mode: os.ModeDir, Children: []*Entry{first, {Name: "nested", Mode: os.ModeDir, Children: []*Entry{&second}}}}
	if r, e := root.RestoreACL(&second, update); e != nil || !r.Applied {
		t.Fatal(r, e)
	}
	for _, entry := range []*Entry{first, &second} {
		if len(entry.Xattrs[hostdata.SecurityName]) != 44 || entry.Mode != 0 || !entry.ModeExplicit || entry.UID != 42 || entry.GID != 43 {
			t.Fatal("alias metadata changed", entry)
		}
	}
}
