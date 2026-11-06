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

func TestCarrierNativeResourceFork(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	file, e := os.Create(name)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	if _, e = file.Write([]byte("data")); e != nil {
		t.Fatal(e)
	}
	value := bytes.Repeat([]byte{9}, (1<<20)+3)
	n, e := ReplaceResourceFork(context.Background(), file, bytes.NewReader(value))
	if e != nil || n != int64(len(value)) {
		t.Fatal(n, e)
	}
	fork, e := OpenResourceFork(file, false)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(fork)
	if e != nil {
		t.Fatal(e)
	}
	fork.Close()
	if !bytes.Equal(got, value) {
		t.Fatal("fork bytes")
	}
	if e = os.Rename(name, name+".moved"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(name, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	if n, e = ReplaceResourceFork(context.Background(), file, bytes.NewReader([]byte{1, 2})); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	got, present, e := ReadXattr(file, ResourceForkName, 10)
	if e != nil || !present || !bytes.Equal(got, []byte{1, 2}) {
		t.Fatal(got, present, e)
	}
	if e = os.Remove(name + ".moved"); e != nil {
		t.Fatal(e)
	}
	fork, e = OpenResourceFork(file, false)
	if e != nil {
		t.Fatal(e)
	}
	defer fork.Close()
	got, e = io.ReadAll(fork)
	if e != nil || !bytes.Equal(got, []byte{1, 2}) {
		t.Fatal(got, e)
	}
	if _, e = ReplaceResourceFork(context.Background(), file, bytes.NewReader(nil)); e != nil {
		t.Fatal(e)
	}
	if _, present, e = ReadXattr(file, ResourceForkName, 10); e != nil || present {
		t.Fatal(present, e)
	}
	if pos, e := file.Seek(0, io.SeekCurrent); e != nil || pos != 4 {
		t.Fatal(pos, e)
	}
	if _, e = openNativeResourceFork(-1, false); e == nil {
		t.Fatal("bad fd accepted")
	}
	file.Close()
	if _, e = OpenResourceFork(file, false); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
}
