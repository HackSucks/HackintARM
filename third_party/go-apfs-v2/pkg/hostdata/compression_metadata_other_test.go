//go:build !darwin

package hostdata

import (
	"errors"
	"os"
	"testing"
)

func TestCompressionNativeMetadataRequiresDarwinContext(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "native-query-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = QueryCompression(t.Context(), f, 24); !errors.Is(e, errors.ErrUnsupported) {
		t.Fatal(e)
	}
	if _, e = CompressionVolumeFlags(t.Context(), f); !errors.Is(e, errors.ErrUnsupported) {
		t.Fatal(e)
	}
	// Complete foreign state is exercised by the portable native-corpus replay
	// and decmpfs.Query. It must never be inferred from this host's unrelated bits.
}
