package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func directoryStatFixture(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestCopyDirectoryStatValidation(t *testing.T) {
	source, target := directoryStatFixture(t), directoryStatFixture(t)
	regular := heldfixture.Source(t, 0600)
	alias, err := os.Open(source.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Close()
	for _, pair := range [][2]*os.File{{source, source}, {source, alias}, {regular, target}, {source, regular}} {
		if err := CopyDirectoryStat(pair[0], pair[1]); !errors.Is(err, ErrUnsupportedDirectoryStat) {
			t.Fatalf("invalid pair: %v", err)
		}
	}
	for _, pair := range [][2]*os.File{{nil, target}, {source, nil}} {
		if err := CopyDirectoryStat(pair[0], pair[1]); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("nil: %v", err)
		}
	}
	closed := directoryStatFixture(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]*os.File{{closed, target}, {source, closed}} {
		// Windows File.Stat reports ERROR_INVALID_HANDLE rather than ErrClosed.
		if err := CopyDirectoryStat(pair[0], pair[1]); err == nil {
			t.Fatalf("closed: %v", err)
		}
	}
}

func TestCopyDirectoryStatHeldDirectories(t *testing.T) {
	source, target := directoryStatFixture(t), directoryStatFixture(t)
	for _, f := range []*os.File{source, target} {
		if err := os.WriteFile(filepath.Join(f.Name(), "child"), []byte(f.Name()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	wantTime := time.Unix(1660000000, 123456700)
	if err := os.Chtimes(source.Name(), wantTime, wantTime); err != nil {
		t.Fatal(err)
	}
	before, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	// Both names may be replaced while their descriptors remain bound. Windows
	// may refuse the rename of an open directory, which also protects identity.
	for _, f := range []*os.File{source, target} {
		moved := filepath.Join(t.TempDir(), "moved")
		if err := os.Rename(f.Name(), moved); err != nil {
			if runtime.GOOS == "windows" {
				continue
			}
			t.Fatal(err)
		}
		if err := os.Mkdir(f.Name(), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.Name(), "decoy"), []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := CopyDirectoryStat(source, target); err != nil {
		t.Fatal(err)
	}
	after, err := target.Stat()
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("identity changed: %v", err)
	}
	if !after.ModTime().Equal(wantTime) {
		t.Fatalf("held target timestamp: %v; want %v", after.ModTime(), wantTime)
	}
	for _, f := range []*os.File{source, target} {
		// ReadDir uses the held handle, not its stale name.
		entries, err := f.ReadDir(-1)
		if err != nil || len(entries) != 1 || entries[0].Name() != "child" {
			t.Fatalf("contents changed: %v %v", entries, err)
		}
		if data, err := os.ReadFile(filepath.Join(f.Name(), "decoy")); err == nil && string(data) != "unchanged" {
			t.Fatalf("decoy changed: %q", data)
		}
	}
}
