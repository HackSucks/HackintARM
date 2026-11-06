package hostdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCaptureXattrsHeld(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	name := "user.capture"
	if runtime.GOOS == "windows" {
		name = "USER.CAPTURE"
	}
	if err := SetXattr(f, name, []byte("value")); err != nil {
		t.Fatal(err)
	}
	limits := XattrCaptureLimits{MaxXattrListSize, 32 << 20, 64 << 20}
	values, err := CaptureXattrs(context.Background(), f, limits)
	if err != nil || !bytes.Equal(values[name], []byte("value")) {
		t.Fatalf("%v: %v", values, err)
	}
	if _, err := CaptureXattrs(context.Background(), f, XattrCaptureLimits{}); !errors.Is(err, ErrXattrTooLarge) {
		t.Fatalf("zero budget: %v", err)
	}
	for _, limit := range []XattrCaptureLimits{{-1, 0, 0}, {MaxXattrListSize + 1, 0, 0}, {0, -1, 0}, {0, 0, -1}} {
		if _, err := CaptureXattrs(context.Background(), f, limit); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	}
	//nolint:staticcheck // Deliberately exercise rejection of a nil context.
	if _, err := CaptureXattrs(nil, f, limits); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := CaptureXattrs(context.Background(), nil, limits); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CaptureXattrs(ctx, f, limits); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCaptureXattrsFailures(t *testing.T) {
	ctx := context.Background()
	fault := errors.New("injected IO")
	limits := XattrCaptureLimits{100, 10, 15}
	names := func() ([]string, error) { return []string{"one", "two"}, nil }
	get := func(_ string, b []byte) (int, error) {
		if b != nil {
			copy(b, "1234567890")
		}
		return 10, nil
	}
	if values, err := captureXattrs(ctx, limits, names, get); values != nil || !errors.Is(err, ErrXattrTooLarge) {
		t.Fatalf("%v %v", values, err)
	}
	if _, err := captureXattrs(ctx, limits, func() ([]string, error) { return nil, fault }, get); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := captureXattrs(ctx, limits, names, func(string, []byte) (int, error) { return 0, missingXattrError }); !errors.Is(err, ErrXattrChanged) {
		t.Fatal(err)
	}
	if _, err := captureXattrs(ctx, limits, names, func(string, []byte) (int, error) { return 0, fault }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	if _, err := captureXattrs(canceled, limits, func() ([]string, error) { cancel(); return []string{"one"}, nil }, get); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	canceled, cancel = context.WithCancel(ctx)
	if _, err := captureXattrs(canceled, limits, func() ([]string, error) { cancel(); return nil, nil }, get); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCaptureXattrsNoFollow(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "capture"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	name := "user.capture"
	if runtime.GOOS == "windows" {
		name = "USER.CAPTURE"
	}
	if err := SetXattr(f, name, []byte("retained")); err != nil {
		t.Fatal(err)
	}
	limits := XattrCaptureLimits{MaxXattrListSize, 32 << 20, 64 << 20}
	values, err := CaptureXattrsNoFollow(context.Background(), f.Name(), limits)
	if err != nil || string(values[name]) != "retained" {
		t.Fatalf("%v %v", values, err)
	}
	if _, err := CaptureXattrsNoFollow(context.Background(), f.Name()+"missing", limits); err == nil {
		t.Fatal("missing file accepted")
	}
	//nolint:staticcheck // Deliberately exercise rejection of a nil context.
	if _, err := CaptureXattrsNoFollow(nil, f.Name(), limits); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := CaptureXattrsNoFollow(context.Background(), f.Name(), XattrCaptureLimits{-1, 0, 0}); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
}
