//go:build native_path_limits_fresh

package recompression

import (
	"os"
	"testing"
)

// TestFreshNativePathLimits is an explicit bootstrap command for one fresh
// capture. The ordinary TestNativePathLimits always requires 15/26/27, including
// when fresh evidence is supplied; this helper does not replace that gate.
func TestFreshNativePathLimits(t *testing.T) {
	name := os.Getenv("APFS_PATHNAME_LIMITS_CAPTURE")
	if name == "" {
		t.Fatal("fresh native capture path is required")
	}
	replayNativePathLimits(t, name)
}
