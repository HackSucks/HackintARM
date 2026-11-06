package hfsplus

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestImageACLRestoreLazyPayload(t *testing.T) {
	fork := []byte("resource fork")
	target := &Entry{Name: "lazy", Mode: 0644, Size: 1 << 40, ResourceFork: fork, Open: func() (io.ReadCloser, error) {
		t.Fatal("ACL staging read the file payload")
		return nil, fs.ErrInvalid
	}}
	root := &Entry{Children: []*Entry{target}}
	result, err := root.RestoreACL(target, appledouble.ACLUpdate{ACL: &appledouble.ACL{}})
	if err != nil || !result.Applied || target.Size != 1<<40 || string(target.ResourceFork) != "resource fork" || target.Open == nil {
		t.Fatal("payload metadata changed", result, err)
	}
}

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
