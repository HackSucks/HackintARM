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

type forkSink struct {
	bytes.Buffer
	truncateErr, writeErr, closeErr error
	short, invalid                  bool
	closeCount                      int
	writeHook                       func()
}

func (f *forkSink) Truncate(int64) error { f.Reset(); return f.truncateErr }
func (f *forkSink) Close() error         { f.closeCount++; return f.closeErr }
func (f *forkSink) Write(p []byte) (int, error) {
	if f.writeHook != nil {
		f.writeHook()
	}
	if f.invalid {
		return len(p) + 1, nil
	}
	if f.short {
		return 0, nil
	}
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.Buffer.Write(p)
}

type forkValueFault struct {
	size  int64
	n     int
	err   error
	calls int
}

func (f *forkValueFault) Size() int64 {
	f.calls++
	if f.size == -2 && f.calls > 2 {
		return 2
	}
	if f.size == -2 {
		return 1
	}
	return f.size
}
func (f *forkValueFault) ReadAt(p []byte, _ int64) (int, error) { return min(f.n, len(p)), f.err }
func TestCarrierResourceForkCopy(t *testing.T) {
	for _, size := range []int{0, 1, 65535, 65536, 65537, 2 << 20} {
		data := bytes.Repeat([]byte{8}, size)
		f := &forkSink{}
		n, e := replaceResourceForkUsing(context.Background(), bytes.NewReader(data), func() (resourceForkSink, error) { return f, nil })
		if e != nil || n != int64(size) || !bytes.Equal(f.Bytes(), data) || f.closeCount != 1 {
			t.Fatal(size, n, e)
		}
	}
	for _, test := range []string{"nil-context", "nil-value", "negative", "cancel", "open", "truncate", "read-short", "read-error", "write-short", "write-error", "write-invalid", "close", "late-cancel", "change", "cancel-open"} {
		t.Run(test, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var value appledouble.Value = bytes.NewReader([]byte{1})
			sink := &forkSink{}
			open := func() (resourceForkSink, error) { return sink, nil }
			switch test {
			case "nil-context":
				ctx = nil
			case "nil-value":
				value = nil
			case "negative":
				value = &forkValueFault{size: -1}
			case "cancel":
				cancel()
			case "open":
				open = func() (resourceForkSink, error) { return nil, fs.ErrPermission }
			case "truncate":
				sink.truncateErr = fs.ErrPermission
			case "read-short":
				value = &forkValueFault{size: 1, err: io.EOF}
			case "read-error":
				value = &forkValueFault{size: 1, n: 1, err: io.ErrClosedPipe}
			case "write-short":
				sink.short = true
			case "write-error":
				sink.writeErr = io.ErrClosedPipe
			case "write-invalid":
				sink.invalid = true
			case "close":
				sink.closeErr = io.ErrClosedPipe
			case "late-cancel":
				value = bytes.NewReader(make([]byte, 65537))
				sink.writeHook = cancel
			case "change":
				value = &forkValueFault{size: -2, n: 1}
			case "cancel-open":
				open = func() (resourceForkSink, error) { cancel(); return sink, nil }
			}
			if _, e := replaceResourceForkUsing(ctx, value, open); e == nil {
				t.Fatal("accepted failure")
			}
		})
	}
	if _, e := ReplaceResourceFork(context.Background(), nil, bytes.NewReader(nil)); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
}
func TestCarrierResourceForkIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	file, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	open := func(int, bool) (*os.File, error) { return os.Open(path) }
	fork, e := openResourceForkUsing(file, false, open)
	if e != nil {
		t.Fatal(e)
	}
	fork.Close()
	if _, e = openResourceForkUsing(nil, false, open); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
	directory, e := os.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer directory.Close()
	if _, e = openResourceForkUsing(directory, false, open); !errors.Is(e, errors.ErrUnsupported) {
		t.Fatal(e)
	}
	if _, e = openResourceForkUsing(file, false, func(int, bool) (*os.File, error) { return nil, io.ErrClosedPipe }); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal(e)
	}
	other, e := os.Create(filepath.Join(dir, "other"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = openResourceForkUsing(file, false, func(int, bool) (*os.File, error) { return other, nil }); !errors.Is(e, ErrMetadataIdentity) {
		t.Fatal(e)
	}
	closed, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	closed.Close()
	if _, e = openResourceForkUsing(file, false, func(int, bool) (*os.File, error) { return closed, nil }); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	file.Close()
	_, statErr := file.Stat()
	var pathErr *os.PathError
	if !errors.As(statErr, &pathErr) {
		t.Fatalf("closed stat: %v", statErr)
	}
	if _, e = openResourceForkUsing(file, false, open); !errors.Is(e, pathErr.Err) {
		t.Fatalf("closed source: %v; want cause %v", e, pathErr.Err)
	}
}
