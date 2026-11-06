//go:build !darwin

package hostdata

import (
	"errors"
	"os"
	"testing"
)

func TestNativeCompressionOwnedForeignHost(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "native-binding-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = NewNativeCompressionInput(t.Context(), file); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err = QueryCompressionVolume(t.Context(), file); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err = file.Stat(); err != nil {
		t.Fatal("failed native binding closed foreign payload", err)
	}
}
