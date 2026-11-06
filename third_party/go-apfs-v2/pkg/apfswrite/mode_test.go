package apfswrite

import (
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/hostwalk"
)

func TestImageModeCapturedEntry(t *testing.T) {
	// The walk synthesizes an anonymous root; its zero mode must keep defaults.
	root, _, err := EntryTreeFromDir(t.TempDir(), nil)
	if err != nil || root.ModeExplicit || root.Mode != 0 {
		t.Fatal("synthetic root changed", root, err)
	}

	for _, mode := range []os.FileMode{0, os.ModeDir, os.ModeSymlink, os.ModeSetuid | os.ModeSetgid | os.ModeSticky, os.ModeDir | 0711 | os.ModeSetgid} {
		e := newEntry(hostwalk.Node{Name: "captured", Mode: mode, UID: 42, GID: 43}, nil)
		if !e.ModeExplicit || e.Mode != mode || e.UID != 42 || e.GID != 43 {
			t.Fatal("captured mode lost", e)
		}
		if mode.Perm() == 0 && e.resolvedMode()&0777 != 0 {
			t.Fatal("captured zero defaulted")
		}
	}
	// APFS supports legacy directory inference from children with Mode==0;
	// marking permissions explicit must not change that type decision.
	e := &Entry{ModeExplicit: true, Children: []*Entry{{Name: "child"}}}
	if e.resolvedMode() != 040000 {
		t.Fatal("inferred directory type lost")
	}
	e.ModeExplicit = false
	if e.resolvedMode() != 040755 {
		t.Fatal("legacy directory default lost")
	}
}
