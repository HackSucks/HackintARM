//go:build !darwin

package osversion

import (
	"context"
	"errors"
	"testing"
)

func TestDetectForeignHost(t *testing.T) {
	if _, err := Detect(t.Context()); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Detect(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Native detection is independent of the fully available target selection.
	for _, major := range []uint32{15, 26, 27} {
		if got, err := ProfileForMacOS(Version{Major: major}); err != nil || uint32(got) != major {
			t.Fatal(got, err)
		}
	}
}
