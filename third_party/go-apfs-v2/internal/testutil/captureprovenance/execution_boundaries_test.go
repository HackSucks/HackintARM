package captureprovenance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

var errExecutionIO = errors.New("execution boundary unavailable")

type receiptIO struct {
	bytes.Buffer
	readErr, writeErr, closeErr error
	closed                      bool
}

func (r *receiptIO) Read(b []byte) (int, error) {
	if r.readErr != nil {
		return 0, r.readErr
	}
	return r.Buffer.Read(b)
}
func (r *receiptIO) Write(b []byte) (int, error) {
	if r.writeErr != nil {
		return 0, r.writeErr
	}
	return r.Buffer.Write(b)
}
func (r *receiptIO) Close() error { r.closed = true; return r.closeErr }

// Exercise failures independent of root privileges, Windows ACLs, and whether
// a particular runner filesystem supports symlinks or Unix device files.
func TestExecutionReadWriteAndCloseFailures(t *testing.T) {
	for _, failure := range []string{"read", "close"} {
		r := &receiptIO{}
		if failure == "read" {
			r.readErr = errExecutionIO
		} else {
			r.closeErr = errExecutionIO
		}
		if _, err := hashExecutionReader(t.Context(), r); !errors.Is(err, errExecutionIO) || !r.closed {
			t.Fatalf("%s: error=%v closed=%v", failure, err, r.closed)
		}
	}
	for _, failure := range []string{"write", "close"} {
		r := &receiptIO{}
		if failure == "write" {
			r.writeErr = errExecutionIO
		} else {
			r.closeErr = errExecutionIO
		}
		if err := writeExecutionReceipt(r, ExecutionReceipt{}); !errors.Is(err, errExecutionIO) || !r.closed {
			t.Fatalf("%s: error=%v closed=%v", failure, err, r.closed)
		}
	}
}

func TestExecutionGitFailuresAndUnsafeInventories(t *testing.T) {
	dir := executionFixture(t)
	for _, failure := range []string{"revision", "inventory", "unsafe", "missing"} {
		git := func(args ...string) ([]byte, error) {
			if args[0] == "rev-parse" {
				if failure == "revision" {
					return nil, errExecutionIO
				}
				return []byte("revision\n"), nil
			}
			switch failure {
			case "inventory":
				return nil, errExecutionIO
			case "unsafe":
				return []byte("../outside\x00"), nil
			default:
				return []byte("missing\x00"), nil
			}
		}
		if _, err := currentExecution(t.Context(), git); err == nil {
			t.Fatal("accepted", failure)
		}
	}
	for key, value := range map[string]string{"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "consumer"} {
		t.Setenv(key, value)
	}
	current, err := CurrentExecution(t.Context())
	if err != nil || current.Run != "123" || current.Attempt != "2" || current.Job != "consumer" {
		t.Fatal(current, err)
	}
	if err := os.Remove("input.go"); err != nil {
		t.Fatal(err)
	}
	if err := SealExecution(t.Context(), dir); err == nil {
		t.Fatal("missing tracked input accepted")
	}
	if err := os.WriteFile("input.go", []byte("restored"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SealExecution(t.Context(), filepath.Join(dir, "native.json")); err == nil {
		t.Fatal("file used as artifact directory")
	}
	if err := SealExecution(t.Context(), t.TempDir()); err == nil {
		t.Fatal("empty evidence sealed")
	}
}

type artifactFaultFS struct {
	fs.FS
	failRead bool
}

func (f artifactFaultFS) Open(name string) (fs.File, error) {
	if name == "native.json" {
		if !f.failRead {
			return nil, errExecutionIO
		}
		file, err := f.FS.Open(name)
		if err != nil {
			return nil, err
		}
		return artifactFaultFile{file}, nil
	}
	return f.FS.Open(name)
}

type artifactFaultFile struct{ fs.File }

func (f artifactFaultFile) Read([]byte) (int, error) { return 0, errExecutionIO }

func TestExecutionArtifactFailuresAndNestedInventories(t *testing.T) {
	source := fstest.MapFS{"native.json": {Data: []byte("native")}, "details/input": {Data: []byte("input")}}
	hashes, err := artifactFiles(t.Context(), source)
	if err != nil || len(hashes) != 2 || hashes["details/input"] == "" {
		t.Fatal(hashes, err)
	}
	for _, read := range []bool{false, true} {
		if _, err := artifactFiles(t.Context(), artifactFaultFS{source, read}); !errors.Is(err, errExecutionIO) {
			t.Fatal("artifact I/O failure lost", err)
		}
	}
	source["link"] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("native.json")}
	if _, err := artifactFiles(t.Context(), source); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatal("linked artifact accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := hashExecutionReader(ctx, io.NopCloser(strings.NewReader("input"))); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
