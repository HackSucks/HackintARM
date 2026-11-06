package cirunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCaptureRetainsSeparateStreamsAndReleasesFiles(t *testing.T) {
	r, _ := testReporter(t)
	for _, mode := range []string{"bytes", "exit", "json-diagnostics"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			stdout, stderr := filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")
			c := helper(t, mode, r)
			err := c.Capture(stdout, stderr)
			var exited *exec.ExitError
			if mode == "exit" {
				if !errors.As(err, &exited) || exited.ExitCode() != 7 {
					t.Fatal("original exit status lost", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			out, err := os.ReadFile(stdout)
			if err != nil {
				t.Fatal(err)
			}
			diagnostics, err := os.ReadFile(stderr)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "bytes":
				if !bytes.Equal(out, []byte("out\x00\xff\n")) || !bytes.Equal(diagnostics, []byte("err\x00\xfe\n")) {
					t.Fatal("raw stream bytes changed")
				}
			case "exit":
				if string(out) != "partial" || !bytes.Equal(diagnostics, bytes.Repeat([]byte("abcdefgh"), 20000)) {
					t.Fatal("failure evidence lost")
				}
			case "json-diagnostics":
				if string(out) != "{\"Action\":\"pass\"}\n" || string(diagnostics) != "go: downloading fixture.invalid/module v1.0.0\n" {
					t.Fatal("tool diagnostics contaminated structured output")
				}
			}
			// This also asserts release of both file handles on Windows.
			for _, name := range []string{stdout, stderr} {
				if err := os.Remove(name); err != nil {
					t.Fatal("capture left an open file", err)
				}
			}
		})
	}
}

func TestCaptureRejectsExistingEvidenceAndConfiguredOutput(t *testing.T) {
	r, _ := testReporter(t)
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	if err := os.WriteFile(second, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	c := helper(t, "bytes", r)
	if err := c.Capture(first, second); !errors.Is(err, os.ErrExist) || c.Process != nil {
		t.Fatal("existing evidence reused or command started", err)
	}
	if err := os.Remove(first); err != nil {
		t.Fatal("first output not closed after second open failed", err)
	}
	c = helper(t, "bytes", r)
	if err := c.Capture(second, first); !errors.Is(err, os.ErrExist) || c.Process != nil {
		t.Fatal("existing stdout overwritten", err)
	}
	for _, stdout := range []bool{false, true} {
		c := helper(t, "bytes", r)
		if stdout {
			c.Stdout = io.Discard
		} else {
			c.Stderr = io.Discard
		}
		if err := c.Capture(first, second); err == nil || c.Process != nil {
			t.Fatal("caller output replaced", err)
		}
	}
	data, err := os.ReadFile(second)
	if err != nil || string(data) != "original" {
		t.Fatal("previous evidence changed", err)
	}
}

type captureCloser struct {
	bytes.Buffer
	err    error
	closed bool
}

func (c *captureCloser) Close() error { c.closed = true; return c.err }

func TestCaptureJoinsCloseFailuresAndPreservesCancellation(t *testing.T) {
	r, _ := testReporter(t)
	out, diagnostic := &captureCloser{err: io.ErrClosedPipe}, &captureCloser{err: os.ErrPermission}
	c := helper(t, "exit", r)
	err := c.capture("out", "err", func(name string) (io.WriteCloser, error) {
		if name == "out" {
			return out, nil
		}
		return diagnostic, nil
	})
	var exited *exec.ExitError
	if !out.closed || !diagnostic.closed || !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, os.ErrPermission) || !errors.As(err, &exited) || exited.ExitCode() != 7 {
		t.Fatal("capture failures or closure lost", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c = CommandContext(ctx, os.Args[0], "-test.run=^TestCommandHelper$")
	c.Options.Reporter = r
	dir := t.TempDir()
	stdout, stderr := filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")
	if err := c.Capture(stdout, stderr); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	for _, name := range []string{stdout, stderr} {
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunWithDiagnostics(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := filepath.Join(t.TempDir(), "command.stderr.log")
	reporter, _ := testReporter(t)
	command := helper(t, "json-diagnostics", reporter)
	command.Stdout = stdout
	if err := command.RunWithDiagnostics(stderr); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(bytes.TrimSpace(stdout.Bytes())) {
		t.Fatal("structured stdout corrupted", stdout.String())
	}
	diagnostic, err := os.ReadFile(stderr)
	if err != nil || !bytes.Contains(diagnostic, []byte("go: downloading")) {
		t.Fatal("diagnostic lost", err)
	}
	if err := os.Remove(stderr); err != nil {
		t.Fatal("diagnostic handle retained", err)
	}
}

func TestRunWithDiagnosticsFailureLifecycle(t *testing.T) {
	reporter, _ := testReporter(t)
	existing := filepath.Join(t.TempDir(), "prior.stderr.log")
	if err := os.WriteFile(existing, []byte("prior"), 0600); err != nil {
		t.Fatal(err)
	}
	command := helper(t, "bytes", reporter)
	if err := command.RunWithDiagnostics(existing); !errors.Is(err, os.ErrExist) || command.Process != nil {
		t.Fatal("prior diagnostics reused", err)
	}
	command = helper(t, "bytes", reporter)
	command.Stderr = io.Discard
	if err := command.RunWithDiagnostics(existing); err == nil || command.Process != nil {
		t.Fatal("configured diagnostics replaced", err)
	}
	diagnostic := &captureCloser{err: io.ErrClosedPipe}
	command = helper(t, "exit", reporter)
	command.Stdout = io.Discard
	err := command.runWithDiagnostics("diagnostics", func(string) (io.WriteCloser, error) { return diagnostic, nil })
	var status *exec.ExitError
	if !diagnostic.closed || !errors.Is(err, io.ErrClosedPipe) || !errors.As(err, &status) || status.ExitCode() != 7 || diagnostic.Len() != 160000 {
		t.Fatal("original exit or failed-close evidence lost", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	command = CommandContext(ctx, os.Args[0], "-test.run=^TestCommandHelper$")
	command.Options.Reporter = reporter
	path := filepath.Join(t.TempDir(), "canceled.stderr.log")
	if err := command.RunWithDiagnostics(path); !errors.Is(err, context.Canceled) || command.Process != nil {
		t.Fatal("cancellation lost", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal("canceled command retained diagnostics handle", err)
	}
}
