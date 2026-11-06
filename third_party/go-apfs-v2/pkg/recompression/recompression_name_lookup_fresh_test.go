//go:build native_name_lookup_fresh

package recompression

import (
	"os"
	"testing"
)

// This bootstrap helper never replaces the default three-profile baseline gate.
func TestFreshNativeNameLookup(t *testing.T) {
	name := os.Getenv("APFS_NAME_LOOKUP_CAPTURE")
	if name == "" {
		t.Fatal("fresh native lookup capture is required")
	}
	replayNativeNameLookup(t, name)
}
