//go:build !darwin

package hostdata

import (
	"context"
	"errors"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func TestQuarantineFileNativeUnavailable(t *testing.T) {
	file := heldfixture.Source(t, 0600)
	if _, err := CaptureQuarantineFile(context.Background(), file, 0); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if err := ApplyQuarantineFile(context.Background(), file, nil, QuarantineProcessCapture{}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
}
