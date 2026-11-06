//go:build !darwin

package hostdata

import (
	"context"
	"errors"
	"testing"
)

func TestQuarantineCaptureNativeUnavailable(t *testing.T) {
	if _, err := CaptureQuarantineProcess(context.Background()); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("native capture: %v", err)
	}
}
