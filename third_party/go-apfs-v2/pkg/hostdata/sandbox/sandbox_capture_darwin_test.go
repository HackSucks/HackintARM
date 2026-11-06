package sandbox

import (
	"errors"
	"testing"
)

func TestSandboxCaptureNative(t *testing.T) {
	_, err := CaptureAppSandbox()
	if err != nil {
		t.Fatal(err)
	}
	original := loadAppSandbox
	defer func() { loadAppSandbox = original }()
	marker := errors.New("sandbox symbol failed")
	loadAppSandbox = func() (func() bool, error) { return nil, marker }
	if _, err = CaptureAppSandbox(); !errors.Is(err, marker) {
		t.Fatal(err)
	}
}
