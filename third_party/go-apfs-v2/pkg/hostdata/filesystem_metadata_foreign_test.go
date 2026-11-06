//go:build linux || windows

package hostdata

import (
	"os"
	"testing"
)

func TestFilesystemMetadataNativeVolumeQuery(t *testing.T) {
	v, _, _ := newMetadataTestView(t, false)
	if _, err := filesystemUsesAppleDouble(v.file); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystemUsesAppleDoubleFD(-1); err == nil {
		t.Fatal("invalid descriptor accepted")
	}
	if err := v.file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystemUsesAppleDouble(v.file); err == nil {
		t.Fatal("closed file accepted")
	}
	if _, err := filesystemUsesAppleDouble((*os.File)(nil)); err == nil {
		t.Fatal("nil file accepted")
	}
}
