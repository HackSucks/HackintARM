package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestCarrierCaptureValueProtocol(t *testing.T) {
	ctx := context.Background()
	limits := XattrCaptureLimits{NameBytes: 100, ValueBytes: 2, TotalBytes: 2}
	list := func() ([]string, error) { return []string{"small", ResourceForkName}, nil }
	get := func(name string, p []byte) (int, error) {
		if name != "small" {
			t.Fatal("fork was materialized")
		}
		if p != nil {
			copy(p, "ab")
		}
		return 2, nil
	}
	fork := func() (appledouble.Value, error) { return bytes.NewReader(make([]byte, 1<<20)), nil }
	values, e := captureXattrValues(ctx, limits, list, get, fork)
	if e != nil || values[ResourceForkName].Size() != 1<<20 || values["small"].Size() != 2 {
		t.Fatal(values, e)
	}
	cases := []string{"list", "cancel", "duplicate", "fork", "fallback", "get", "missing", "limit", "late-cancel"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l := list
			g := get
			f := fork
			switch name {
			case "list":
				l = func() ([]string, error) { return nil, io.ErrClosedPipe }
			case "cancel":
				cancel()
			case "duplicate":
				l = func() ([]string, error) { return []string{"small", "small"}, nil }
			case "fork":
				f = func() (appledouble.Value, error) { return nil, io.ErrClosedPipe }
			case "fallback":
				l = func() ([]string, error) { return []string{ResourceForkName}, nil }
				f = func() (appledouble.Value, error) { return nil, errors.ErrUnsupported }
				g = func(_ string, p []byte) (int, error) { copy(p, "a"); return 1, nil }
			case "get":
				g = func(string, []byte) (int, error) { return 0, io.ErrClosedPipe }
			case "missing":
				g = func(string, []byte) (int, error) { return 0, missingXattrError }
			case "limit":
				g = func(string, []byte) (int, error) { return 3, nil }
			case "late-cancel":
				l = func() ([]string, error) { cancel(); return nil, nil }
			}
			values, e := captureXattrValues(ctx, limits, l, g, f)
			if name == "fallback" {
				if e != nil || values[ResourceForkName].Size() != 1 {
					t.Fatal(values, e)
				}
			} else if e == nil {
				t.Fatal("accepted failed capture")
			}
		})
	}
}
func TestCarrierCaptureValuesValidation(t *testing.T) {
	if _, e := CaptureXattrValues(nil, nil, XattrCaptureLimits{}); !errors.Is(e, fs.ErrInvalid) { //nolint:staticcheck // Explicitly test rejection of an invalid nil context.
		t.Fatal(e)
	}
	for _, l := range []XattrCaptureLimits{{NameBytes: -1}, {NameBytes: MaxXattrListSize + 1}, {ValueBytes: -1}, {TotalBytes: -1}} {
		if _, e := CaptureXattrValues(context.Background(), nil, l); !errors.Is(e, fs.ErrInvalid) {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := CaptureXattrValues(ctx, nil, XattrCaptureLimits{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := CaptureXattrValues(context.Background(), nil, XattrCaptureLimits{}); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := CaptureXattrValuesAt(context.Background(), nil, "file", XattrCaptureLimits{}); e == nil {
		t.Fatal("nilroot")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file"), nil, 0600)
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if _, e = CaptureXattrValuesAt(nil, root, "file", XattrCaptureLimits{}); !errors.Is(e, fs.ErrInvalid) { //nolint:staticcheck // Explicitly test rejection of an invalid nil context.
		t.Fatal(e)
	}
	f, e := root.Open("file")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = SetXattr(f, "user.nativevalue", []byte("abc")); e != nil {
		t.Fatal(e)
	}
	values, e := CaptureXattrValuesAt(context.Background(), root, "file", XattrCaptureLimits{NameBytes: MaxXattrListSize, ValueBytes: 1 << 20, TotalBytes: 2 << 20})
	if e != nil || len(values) == 0 {
		t.Fatal(values, e)
	}
}
func TestCarrierBorrowedForkReads(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	os.WriteFile(name, []byte("abc"), 0600)
	open := func() (*os.File, error) { return os.Open(name) }
	v, e := borrowResourceFork(context.Background(), open)
	if e != nil {
		t.Fatal(e)
	}
	if v.Size() != 3 {
		t.Fatalf("captured fork size = %d, want 3", v.Size())
	}
	p := make([]byte, 5)
	if n, e := v.ReadAt(p, 0); n != 3 || !errors.Is(e, io.EOF) || string(p[:3]) != "abc" {
		t.Fatal(n, e)
	}
	if _, e = v.ReadAt(nil, 0); e != nil {
		t.Fatal(e)
	}
	if _, e = v.ReadAt(p, -1); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
	os.WriteFile(name, []byte("changed"), 0600)
	if _, e = v.ReadAt(p, 0); !errors.Is(e, ErrXattrChanged) {
		t.Fatal(e)
	}
	os.Remove(name)
	if _, e = v.ReadAt(p, 0); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	if _, e = borrowResourceFork(context.Background(), open); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	f, e := os.Create(name)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	closed := func() (*os.File, error) { return f, nil }
	if _, e = borrowResourceFork(context.Background(), closed); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value := &resourceForkValue{ctx: ctx, open: open}
	if _, e = value.ReadAt(p, 0); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	value.ctx = context.Background()
	value.open = closed
	if _, e = value.ReadAt(p, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
}

func TestCarrierCaptureValueRootFailures(t *testing.T) {
	for _, test := range []string{"initial-stat", "initial-close", "read-open", "read-identity", "read-stat", "fork", "read-close", "success"} {
		t.Run(test, func(t *testing.T) {
			dir := t.TempDir()
			name := filepath.Join(dir, "file")
			os.WriteFile(name, []byte("abc"), 0600)
			// A distinct real file exercises identity rejection independently of
			// Darwin's resource-fork namespace on every supported host.
			if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte("xyz"), 0600); err != nil {
				t.Fatal(err)
			}
			root, e := os.OpenRoot(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			calls := 0
			var openedFork *os.File
			ops := xattrValueOps{
				open: func(r *os.Root, n string) (*os.File, error) {
					calls++
					if calls == 2 && test == "read-open" {
						return nil, os.ErrNotExist
					}
					if calls == 2 && test == "read-identity" {
						n = "replacement"
					}
					f, e := r.Open(n)
					if e == nil && ((test == "initial-stat" && calls == 1) || (test == "read-stat" && calls == 2)) {
						f.Close()
					}
					return f, e
				},
				capture: func(ctx context.Context, f *os.File, _ XattrCaptureLimits) (map[string]appledouble.Value, error) {
					if test == "initial-close" {
						f.Close()
					}
					return map[string]appledouble.Value{ResourceForkName: &resourceForkValue{ctx: ctx, size: 3}}, nil
				},
				fork: func(f *os.File) (*os.File, error) {
					if test == "fork" {
						return nil, io.ErrClosedPipe
					}
					var e error
					openedFork, e = os.Open(name)
					if test == "read-close" {
						f.Close()
					}
					return openedFork, e
				},
			}
			values, e := captureXattrValuesAt(context.Background(), root, "file", XattrCaptureLimits{}, ops)
			if test == "initial-stat" || test == "initial-close" {
				if e == nil || values != nil {
					t.Fatal(values, e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			p := make([]byte, 3)
			n, e := values[ResourceForkName].ReadAt(p, 0)
			if test == "success" {
				if e != nil || n != 3 || string(p) != "abc" {
					t.Fatal(n, e)
				}
				return
			}
			if e == nil {
				t.Fatal("accepted failed read")
			}
			if test == "read-open" && !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("reopen error lost: %v", e)
			}
			if test == "read-identity" && !errors.Is(e, ErrMetadataIdentity) {
				t.Fatalf("replacement identity accepted: %v", e)
			}
			if test == "read-close" {
				// Stat on a closed Windows file reports ERROR_INVALID_HANDLE.
				// A second Close directly checks that ownership was released.
				if e = openedFork.Close(); !errors.Is(e, os.ErrClosed) {
					t.Fatal("fork leaked", e)
				}
			}
		})
	}
}
