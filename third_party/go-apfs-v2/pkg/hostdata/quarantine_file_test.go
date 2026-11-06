package hostdata

import (
	"context"
	"errors"
	"os"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func TestQuarantineFileInvalidArguments(t *testing.T) {
	file := heldfixture.Source(t, 0600)
	//nolint:staticcheck // Exercise the public invalid-context contract.
	if _, err := CaptureQuarantineFile(nil, file, 0); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := CaptureQuarantineFile(context.Background(), nil, 0); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	//nolint:staticcheck // Exercise the public invalid-context contract.
	if err := ApplyQuarantineFile(nil, file, nil, QuarantineProcessCapture{}); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := ApplyQuarantineFile(context.Background(), nil, nil, QuarantineProcessCapture{}); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CaptureQuarantineFile(ctx, file, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := ApplyQuarantineFile(ctx, file, nil, QuarantineProcessCapture{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := ApplyQuarantineFile(context.Background(), file, nil, QuarantineProcessCapture{Profile: 99}); err == nil {
		t.Fatal("invalid profile accepted")
	}
}
