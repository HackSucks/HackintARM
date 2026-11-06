package sandbox

import (
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
)

// Missing dynamic symbols are now link failures, qualified by both Darwin
// architecture builds. The live signed sandbox matrix still independently
// verifies the actual process-state result against Apple's C implementation.
func TestSandboxCaptureTypedWrapper(t *testing.T) {
	got, err := CaptureAppSandbox()
	if err != nil {
		t.Fatal(err)
	}
	if want := darwinabi.AppSandboxed(); got != want {
		t.Fatalf("capture=%t wrapper=%t", got, want)
	}
}
