//go:build darwin || linux || windows

package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCarrierSetFileTimes(t *testing.T) {
	modify := time.Unix(946684800, 123456700)
	access := time.Unix(978307200, 234567800)
	if err := SetFileTimes(nil, modify, access); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil: %v", err)
	}
	for _, directory := range []bool{false, true} {
		name := filepath.Join(t.TempDir(), "object")
		if directory {
			if err := os.Mkdir(name, 0700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(name, []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := openTimeTestFile(name, directory)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := SetFileTimes(file, modify, access); err != nil {
			t.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().Equal(modify) {
			t.Fatalf("modify = %v want %v", info.ModTime(), modify)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		// Stat preserves the host's error: Windows reports an invalid handle,
		// while Unix reports os.ErrClosed. The setter must propagate that cause.
		_, statErr := file.Stat()
		var pathErr *os.PathError
		if !errors.As(statErr, &pathErr) {
			t.Fatalf("closed stat: %v", statErr)
		}
		if err := SetFileTimes(file, modify, access); !errors.Is(err, pathErr.Err) {
			t.Fatalf("closed: %v; want cause %v", err, pathErr.Err)
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := SetFileTimes(w, modify, access); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("pipe: %v", err)
	}
}
