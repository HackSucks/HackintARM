package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCarrierNativeForkCapture(t *testing.T) {
	dir := t.TempDir()
	file, e := os.Create(filepath.Join(dir, "file"))
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	content := bytes.Repeat([]byte{7}, (1<<20)+7)
	if _, e = ReplaceResourceFork(context.Background(), file, bytes.NewReader(content)); e != nil {
		t.Fatal(e)
	}
	limits := XattrCaptureLimits{NameBytes: MaxXattrListSize, ValueBytes: 16384, TotalBytes: 32768}
	values, e := CaptureXattrValues(context.Background(), file, limits)
	if e != nil {
		t.Fatal(e)
	}
	v := values[ResourceForkName]
	if v == nil || v.Size() != int64(len(content)) {
		t.Fatal(values)
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	values, e = CaptureXattrValuesAt(context.Background(), root, "file", limits)
	if e != nil {
		t.Fatal(e)
	}
	at := values[ResourceForkName]
	p := make([]byte, 10)
	if n, e := at.ReadAt(p, at.Size()-3); n != 3 || !errors.Is(e, io.EOF) || !bytes.Equal(p[:3], content[:3]) {
		t.Fatal(n, e)
	}
	os.Rename(filepath.Join(dir, "file"), filepath.Join(dir, "moved"))
	os.WriteFile(filepath.Join(dir, "file"), nil, 0600)
	if _, e = at.ReadAt(p, 0); !errors.Is(e, ErrMetadataIdentity) {
		t.Fatal(e)
	}
	if _, e = v.ReadAt(p, 0); e != nil {
		t.Fatal("held source failed after rename", e)
	}
	os.Remove(filepath.Join(dir, "file"))
	if _, e = at.ReadAt(p, 0); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}
