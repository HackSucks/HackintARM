package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinCallCapturedErrno(t *testing.T) {
	a, err := loadDarwinSecurity()
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if n, err := a.stat(-1, &st, 0); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
	if n, err := darwinSizeResult(1<<33, nil); n != 1<<33 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := darwinSizeResult(-1, syscall.EACCES); n != 0 || !errors.Is(err, syscall.EACCES) {
		t.Fatal(n, err)
	}
	// A native size query on a sparse resource fork proves the typed wrapper's
	// full-width result without allocating or reading the entire fork.
	file, err := os.CreateTemp(t.TempDir(), "fork-width")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fork, err := os.OpenFile(file.Name()+"/..namedfork/rsrc", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Close()
	if _, err := fork.WriteAt([]byte{1}, (1<<33)-1); err != nil {
		t.Fatal(err)
	}
	if err := fork.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := getCaptureXattrFD(int(file.Fd()), "com.apple.ResourceFork", nil); err != nil || n != 1<<33 {
		t.Fatal(n, err)
	}
}

func TestDarwinCallMetadataErrnoUnderScheduling(t *testing.T) {
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing")
	if err := os.WriteFile(existing, nil, 0600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(directory, "missing")
	// An absent filesec property returns ENOENT after successful statx. Under the
	// old two-call errno reader, runtime activity occasionally changed that into
	// EINTR, ETIMEDOUT or even 260, turning successful capture into a false error.
	for worker := 0; worker < 8; worker++ {
		t.Run("worker", func(t *testing.T) {
			t.Parallel()
			for iteration := 0; iteration < 500; iteration++ {
				if _, err := CapturePathMetadata(existing, true); err != nil {
					t.Fatalf("existing iteration%d: %v", iteration, err)
				}
				runtime.Gosched()
				if _, err := CapturePathMetadata(missing, true); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing iteration%d: %v", iteration, err)
				}
			}
		})
	}
}
