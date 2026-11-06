package hostdata

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMetadataStatWindowsEADenied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	metadataStatCommand(t, "icacls", path, "/deny", "*S-1-1-0:(REA)")
	t.Cleanup(func() { metadataStatCommand(t, "icacls", path, "/remove:d", "*S-1-1-0") })
	if _, err := StatMetadata(root, "file"); err != nil {
		t.Fatal("stat requested extended attributes", err)
	}
	if f, err := OpenMetadataFileRead(root, "file"); err == nil {
		f.Close()
		t.Fatal("EA denial ineffective")
	}
}
