package cirunner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestForwardFileLiveExactFloodAndFinalDrain(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "raw")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := &synchronizedBuffer{}
	forward := ForwardFile(f, out)
	first := []byte("before child exit\x00\xff\n")
	if _, err = f.Write(first); err != nil {
		t.Fatal(err)
	}
	waitText(t, out, string(first))
	flood := bytes.Repeat([]byte{0, 1, 2, 255, '\n'}, 70000)
	if _, err = f.Write(flood); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err = forward.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), first...), flood...)
	if !bytes.Equal([]byte(out.String()), want) {
		t.Fatal("forwarded bytes changed")
	}
	if err = forward.Stop(ctx); err != nil {
		t.Fatal("repeat stop", err)
	}
	raw, err := os.ReadFile(f.Name())
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatal("raw file changed", err)
	}
	if _, err = f.WriteString("caller still owns descriptor"); err != nil {
		t.Fatal(err)
	}
}

func TestForwardFileBlockedDestinationHasBoundedStop(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "raw")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.WriteString("first")
	b := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	forward := ForwardFile(f, b)
	<-b.entered
	// Native writes continue while the independently opened reader is blocked.
	if _, err = f.WriteString("last"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err = forward.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal("reader retained caller descriptor", err)
	}
	close(b.release)
	if err = forward.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b.out.String() != "firstlast" {
		t.Fatal("partial final drain", b.out.String())
	}
}

func TestForwardFileOpenWriteAndIdentityFailures(t *testing.T) {
	for _, test := range []string{"missing", "directory", "error", "short", "replace", "remove"} {
		t.Run(test, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "raw")
			f := createMovableFile(t, path)
			var err error
			defer f.Close()
			_, _ = f.WriteString("payload")
			var writer io.Writer = io.Discard
			switch test {
			case "missing":
				if err = os.Rename(path, path+"-held"); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err = os.Rename(path, path+"-held"); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "error":
				writer = errorWriter{err: io.ErrClosedPipe}
			case "short":
				writer = errorWriter{short: true}
			}
			if test == "replace" || test == "remove" {
				b := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
				forward := ForwardFile(f, b)
				var release sync.Once
				t.Cleanup(func() {
					release.Do(func() { close(b.release) })
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					_ = forward.Stop(ctx)
				})
				<-b.entered
				if err = os.Rename(path, path+"-held"); err != nil {
					t.Fatal(err)
				}
				if test == "remove" {
					if err = os.Remove(path + "-held"); err != nil {
						t.Fatal(err)
					}
				}
				if test == "replace" {
					if err = os.WriteFile(path, []byte("other"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				release.Do(func() { close(b.release) })
				err = forward.Stop(t.Context())
				if err == nil {
					t.Fatal("lost identity failure")
				}
				if test == "replace" && !strings.Contains(err.Error(), "identity changed") {
					t.Fatal(err)
				}
				return
			}
			forward := ForwardFile(f, writer)
			err = forward.Stop(t.Context())
			if err == nil {
				t.Fatal("expected failure")
			}
			if test == "error" && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			if test == "short" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal(err)
			}
		})
	}
}

type faultForwardInput struct {
	*os.File
	readErr, errorStat error
	eof                bool
}

func (f faultForwardInput) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	if f.eof {
		return 0, io.EOF
	}
	return f.File.Read(p)
}
func (f faultForwardInput) Stat() (os.FileInfo, error) {
	if f.errorStat != nil {
		return nil, f.errorStat
	}
	return f.File.Stat()
}

func TestForwardFileReadSnapshotAndTruncationFailures(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "raw")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.WriteString("payload")
	for _, test := range []struct {
		input faultForwardInput
		want  error
	}{
		{faultForwardInput{File: f, readErr: io.ErrNoProgress}, io.ErrNoProgress},
		{faultForwardInput{File: f, errorStat: io.ErrClosedPipe}, io.ErrClosedPipe},
		{faultForwardInput{File: f, eof: true}, io.ErrUnexpectedEOF},
	} {
		stop := make(chan struct{})
		close(stop)
		forward := &FileForwarder{stop: stop, destination: io.Discard}
		if err = forward.drain(test.input); !errors.Is(err, test.want) {
			t.Fatal(err)
		}
	}
	_, _ = f.Seek(0, io.SeekStart)
	b := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	forward := ForwardFile(f, b)
	<-b.entered
	if err = f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	close(b.release)
	if err = forward.Stop(t.Context()); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatal(err)
	}
}
