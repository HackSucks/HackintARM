package osversion

import (
	"context"

	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestDetectNative(t *testing.T) {
	got, err := Detect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cirunner.CommandContext(t.Context(), "sw_vers", "-productVersion").Output()
	if err != nil {
		t.Fatal(err)
	}
	want, err := Parse(strings.TrimSpace(string(raw)))
	if err != nil || got != want {
		t.Fatal(got, want, err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = Detect(canceled); err != context.Canceled {
		t.Fatal(err)
	}
}
