package imagefile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtAndReadBack(t *testing.T) {
	f, err := New(t.TempDir(), "test-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Write out of order, as a file system writer does: metadata at low
	// offsets, data further in, then the final byte to size the image.
	if _, err := f.WriteAt([]byte("second"), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("first"), 0); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, 6)
	if _, err := f.ReadAt(got, 100); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("read %q, want %q", got, "second")
	}

	// The gap between the two writes must read as zeros, exactly as the
	// in-memory buffer this replaced behaved.
	gap := make([]byte, 95)
	if _, err := f.ReadAt(gap, 5); err != nil {
		t.Fatalf("reading the gap: %v", err)
	}
	if !bytes.Equal(gap, make([]byte, 95)) {
		t.Error("the gap between two writes did not read as zeros")
	}
}

// TestSizeIsTheHighWaterMark checks Size reports one past the highest offset
// written, whichever order the writes arrive in. The writers size an image by
// writing its final byte, so this is what the DMG encoder is told the image
// length is.
func TestSizeIsTheHighWaterMark(t *testing.T) {
	f, err := New(t.TempDir(), "test-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := f.Size(); got != 0 {
		t.Errorf("a fresh file reports size %d, want 0", got)
	}

	if _, err := f.WriteAt([]byte{0}, 4095); err != nil {
		t.Fatal(err)
	}
	if got := f.Size(); got != 4096 {
		t.Errorf("size = %d after writing the byte at 4095, want 4096", got)
	}

	// An earlier write must not lower it.
	if _, err := f.WriteAt(bytes.Repeat([]byte("x"), 16), 0); err != nil {
		t.Fatal(err)
	}
	if got := f.Size(); got != 4096 {
		t.Errorf("size = %d after an earlier write, want it unchanged at 4096", got)
	}
}

// TestCloseRemovesTheFile checks the scratch file does not outlive its use.
func TestCloseRemovesTheFile(t *testing.T) {
	dir := t.TempDir()
	f, err := New(dir, "test-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the scratch file does not exist while in use: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the scratch file survived Close: %v", err)
	}

	// The directory must be left empty, so a caller's temp dir is not littered.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%d file(s) left behind: %v", len(entries), entries)
	}
}

// TestCloseIsIdempotent matters because every call site pairs a deferred Close
// with the possibility of an explicit one, and a double close must not report a
// spurious error.
func TestCloseIsIdempotent(t *testing.T) {
	f, err := New(t.TempDir(), "test-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil", err)
	}
}

// TestCreatedInTheRequestedDirectory checks the scratch file lands where it was
// asked to. That is not cosmetic: the caller chooses a directory on the same
// file system as the output precisely because the system temporary directory
// may be small, or RAM-backed.
func TestCreatedInTheRequestedDirectory(t *testing.T) {
	dir := t.TempDir()
	f, err := New(dir, "scratch-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := filepath.Dir(f.Name()); got != dir {
		t.Errorf("scratch file created in %s, want %s", got, dir)
	}
}

func TestNewInAMissingDirectoryFails(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "absent"), "test-*.tmp"); err == nil {
		t.Error("creating a scratch file in a missing directory succeeded")
	}
}
