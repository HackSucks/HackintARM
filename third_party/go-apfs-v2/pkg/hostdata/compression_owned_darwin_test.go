package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeCompressionOwnedHeldAcquisition(t *testing.T) {
	directory := t.TempDir()
	rootName := filepath.Join(directory, "root")
	if err := os.Mkdir(rootName, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootName)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data := bytes.Repeat([]byte("native ownership"), 4096)
	f, err := root.OpenFile("file", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Seek(19, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(rootName, rootName+"-moved"); err != nil {
		t.Fatal(err)
	}
	input, err := NewNativeCompressionInput(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	position, err := f.Seek(0, io.SeekCurrent)
	if err != nil || position != 19 {
		t.Fatal("binding moved offset", position, err)
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("binding changed object", err)
	}
	volume, err := QueryCompressionVolume(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	var native unix.Statfs_t
	if err = unix.Fstatfs(int(f.Fd()), &native); err != nil {
		t.Fatal(err)
	}
	if volume.Filesystem != unix.ByteSliceToString(native.Fstypename[:]) || volume.Flags != native.Flags {
		t.Fatal(volume, native)
	}
	if err = root.Rename("file", "renamed"); err != nil {
		t.Fatal(err)
	}
	state, err := input.Snapshot()
	if err != nil || state.Size != int64(len(data)) {
		t.Fatal(state, err)
	}
	if err = input.ProbeWrite(); err != nil {
		t.Fatal(err)
	}
	duplicate, err := input.Duplicate()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(data))
	if _, err = duplicate.ReadAt(got, 0); err != nil || !bytes.Equal(data, got) {
		t.Fatal("duplicate content", err)
	}
	if err = duplicate.Close(); err != nil {
		t.Fatal(err)
	}
	if err = input.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("ownership not transferred", err)
	}
	// os.Root enforces containment; bare C openat does not establish this rule.
	if err = root.Symlink("renamed", "internal"); err != nil {
		t.Fatal(err)
	}
	valid, err := root.OpenFile("internal", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = valid.Close(); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(directory, "outside")
	if err = os.WriteFile(outside, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = root.Symlink(outside, "escape"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"escape", "../outside"} {
		if escaped, e := root.OpenFile(name, os.O_RDWR, 0); e == nil {
			escaped.Close()
			t.Fatal("escaped root", name)
		}
	}
}

func TestNativeCompressionOwnedNoAcquisitionCalls(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closed-")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	input, err := NewNativeCompressionInput(t.Context(), f)
	if err != nil {
		t.Fatal("binding performed descriptor observation", err)
	}
	conn, e := f.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	closed := conn.Control(func(uintptr) { t.Fatal("closed descriptor observed") })
	if closed == nil {
		t.Fatal("closed control succeeded")
	}
	if _, err = input.Snapshot(); !errors.Is(err, closed) {
		t.Fatal("snapshot checkpoint", err)
	}
	if err = input.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("close checkpoint", err)
	}
}

func TestNativeCompressionOwnedReadOnlyAdmission(t *testing.T) {
	name := filepath.Join(t.TempDir(), "readonly")
	if err := os.WriteFile(name, bytes.Repeat([]byte("a"), 32768), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewNativeCompressionInput(t.Context(), file)
	if err != nil {
		t.Fatal("binding validated access mode", err)
	}
	harness := newRecompressionHarness(t, nil)
	result, err := Recompress(t.Context(), func(context.Context) (CompressionInput, error) { return input, nil }, harness.options)
	if !result.Accepted || !errors.Is(err, unix.EBADF) || len(result.Failures) == 0 || result.Failures[0].Operation != "probe-write" {
		t.Fatal("changed admission ordering", result, err)
	}
	if err = file.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("read-only input leak", err)
	}
	harness.cleanupCheck()
}
