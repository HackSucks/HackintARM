//go:build !darwin

package hostdata

import (
	"context"
	"errors"
	"testing"
)

func TestNativeCompressionAcquisitionRequiresDarwinContext(t *testing.T) {
	if _, err := OpenNativeCompressionInput(t.Context(), "unused"); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := OpenNativeCompressionInput(ctx, "unused"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
