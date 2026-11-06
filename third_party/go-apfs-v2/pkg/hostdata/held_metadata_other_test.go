//go:build !darwin

package hostdata

import (
	"errors"
	"os"
	"testing"
)

func TestHeldMetadataForeignHost(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := NewHeldMetadata(f); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	logical := logicalMetadataFixture(t)
	if _, err := logical.CaptureSecurity(); err != nil {
		t.Fatal(err)
	}
}
