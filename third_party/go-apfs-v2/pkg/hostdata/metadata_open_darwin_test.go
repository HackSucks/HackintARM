package hostdata

import (
	"os"
	"testing"
)

func TestDarwinMetadataOpenErrors(t *testing.T) {
	if _, err := openDarwinMetadataAt(nil, "name"); err == nil {
		t.Fatal("nil descriptor accepted")
	}
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := openDarwinMetadataAt(f, "missing"); err == nil {
		t.Fatal("missing child accepted")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openDarwinMetadataAt(f, "name"); err == nil {
		t.Fatal("closed descriptor accepted")
	}
}
