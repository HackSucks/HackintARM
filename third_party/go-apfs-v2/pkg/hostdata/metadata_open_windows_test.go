package hostdata

import (
	"os"
	"testing"
)

func TestMetadataOpenWindowsErrors(t *testing.T) {
	if _, err := openWindowsMetadataAt(nil, "name"); err == nil {
		t.Fatal("nil parent accepted")
	}
	if _, err := openWindowsMetadataAt(nil, "bad\x00name"); err == nil {
		t.Fatal("invalid name accepted")
	}
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := openWindowsMetadataAt(f, "missing"); err == nil {
		t.Fatal("missing child accepted")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openWindowsMetadataAt(f, "name"); err == nil {
		t.Fatal("closed parent accepted")
	}
}
