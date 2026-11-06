package cirunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockedWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	out     synchronizedBuffer
}

func (b *blockedWriter) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.out.Write(p)
}

type errorWriter struct {
	err   error
	short bool
}

func (w errorWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.err
}

func TestBlockedReporterCannotDelayCommandsCancellationOrRawOutput(t *testing.T) {
	t.Setenv("APFS_CI_STRICT_REPORTING", "")
	b := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewReporter(b, 1)
	r.emit("blocked")
	<-b.entered
	c := helper(t, "bytes", r)
	start := time.Now()
	got, err := c.Output()
	if err != nil || string(got) != "out\x00\xff\n" {
		t.Fatal("raw output", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("console blocked command")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	c = CommandContext(ctx, os.Args[0], "-test.run=^TestCommandHelper$")
	c.Env = append(withoutHelper(os.Environ()), "CIRUNNER_HELPER=hold")
	c.Options = Options{Reporter: r, Heartbeat: time.Millisecond}
	if err = c.Run(); err == nil {
		t.Fatal("cancelled command succeeded")
	}
	if r.Dropped() == 0 {
		t.Fatal("missing explicit backpressure count")
	}
	deadline, stop := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer stop()
	if err = r.Flush(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(b.release)
	flush(t, r)
	if !strings.Contains(b.out.String(), "raw command evidence remains in caller sinks") {
		t.Fatal("no dropped console report")
	}
	if err = r.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.emit("after close")
	if r.Dropped() < 2 {
		t.Fatal("closed reporter drop not counted")
	}
	if err = r.Flush(t.Context()); err == nil {
		t.Fatal("closed flush succeeded")
	}
	if err = r.Close(t.Context()); err == nil {
		t.Fatal("closed reporter status absent")
	}
}

func TestStrictReportingPreservesExitErrorAndFailsLostEvidence(t *testing.T) {
	t.Setenv("APFS_CI_STRICT_REPORTING", "1")
	r := NewReporter(errorWriter{err: io.ErrClosedPipe}, 8)
	c := helper(t, "exit", r)
	c.Options.StrictReporting = true
	_, err := c.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 || len(exit.Stderr) == 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost exit or reporting error", err)
	}
	_ = r.Close(t.Context())
	r = NewReporter(io.Discard, 8)
	r.dropped.Add(1)
	c = helper(t, "bytes", r)
	if _, err = c.Output(); err == nil || !strings.Contains(err.Error(), "lost 1 console diagnostics") {
		t.Fatal(err)
	}
	_ = r.Close(t.Context())
	b := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	r = NewReporter(b, 8)
	r.emit("held")
	<-b.entered
	c = helper(t, "bytes", r)
	c.Options.StrictReporting = true
	c.Options.FlushTimeout = 10 * time.Millisecond
	if _, err = c.Output(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unbounded/hidden final flush", err)
	}
	close(b.release)
	_ = r.Close(t.Context())
}

func TestReporterWriteErrorsAndBoundedClose(t *testing.T) {
	sentinel := errors.New("console failed")
	for _, writer := range []io.Writer{errorWriter{err: sentinel}, errorWriter{short: true}} {
		r := NewReporter(writer, 0)
		r.emit("entry")
		want := sentinel
		if writer.(errorWriter).short {
			want = io.ErrShortWrite
		}
		if err := r.Flush(t.Context()); !errors.Is(err, want) {
			t.Fatal(err)
		}
		if !errors.Is(r.Err(), want) {
			t.Fatal("missing retained logging error")
		}
		if err := r.Close(t.Context()); !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
	b := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewReporter(b, 2)
	r.emit("entry")
	<-b.entered
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := r.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(b.release)
	select {
	case <-r.done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after write unblocked")
	}
	r = NewReporter(io.Discard, 1)
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	if err := r.Flush(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_ = r.Close(t.Context())
}

func TestDefaultReporterOwnsIndependentJSONLJournal(t *testing.T) {
	if os.Getenv("CIRUNNER_DEFAULT_REPORTER_HELPER") == "1" {
		// The default reporter is process-owned. Test its lifetime in a fresh
		// process so other tests cannot initialize it first or reuse it closed.
		r := DefaultReporter()
		defer func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
			defer cancel()
			if err := r.Close(ctx); err != nil {
				t.Error(err)
			}
		}()
		if r != DefaultReporter() {
			t.Fatal("default reporter not shared")
		}
		c := CommandContext(t.Context(), os.Args[0], "-test.run=^TestCommandHelper$")
		c.Env = append(withoutHelper(os.Environ()), "CIRUNNER_HELPER=bytes")
		raw, err := c.Output()
		if err != nil || !bytes.Equal(raw, []byte("out\x00\xff\n")) {
			t.Fatal(err)
		}
		flush(t, r)
		return
	}
	dir := t.TempDir()
	t.Setenv("APFS_CI_REPORT_DIR", dir)
	r := NewReporter(io.Discard, 256)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
		defer cancel()
		if err := r.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	args := []string{"-test.run=^TestDefaultReporterOwnsIndependentJSONLJournal$"}
	// Keep the real child-process coverage in the parent's coverage run.
	if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+coverage.Value.String())
	}
	c := CommandContext(t.Context(), os.Args[0], args...)
	c.Options.Reporter = r
	c.Env = append(withoutHelper(os.Environ()), "CIRUNNER_DEFAULT_REPORTER_HELPER=1")
	if raw, err := c.CombinedOutput(); err != nil {
		t.Fatalf("default reporter process: %v\n%s", err, raw)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "commands-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatal(paths, err)
	}
	b, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte{'\n'})
	if len(lines) < 3 {
		t.Fatal("missing journal lifecycle", string(b))
	}
	for _, line := range lines {
		var event struct {
			Time    time.Time
			Message string
		}
		if err = json.Unmarshal(line, &event); err != nil || event.Time.IsZero() || event.Message == "" {
			t.Fatal("invalid journal", string(line), err)
		}
	}
	// Windows rejects deletion of an open journal. Require actual release after
	// the owning process completes, rather than depending on TempDir cleanup.
	if err = os.Remove(paths[0]); err != nil {
		t.Fatal(err)
	}
}

func TestJournalFailuresAndIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	j := &journalWriter{directory: path}
	if _, err := j.Write([]byte("phase")); err == nil {
		t.Fatal("journal replaced ordinary file")
	}
	j.close()
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	j = &journalWriter{file: f}
	if _, err = j.Write([]byte("phase")); !errors.Is(err, os.ErrClosed) {
		t.Fatal("write failure hidden", err)
	}
	j.close()
	failed := NewReporter(j, 8)
	failed.emit("closed journal")
	if err = failed.Flush(t.Context()); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if err = failed.Close(t.Context()); !errors.Is(err, os.ErrClosed) {
		t.Fatal("journal close failure hidden", err)
	}
	defaults := NewReporter(nil, 0)
	if err = defaults.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	console := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewReporter(console, 1)
	journal := &synchronizedBuffer{}
	r.journal = NewReporter(journal, 10)
	r.emit("first")
	<-console.entered
	r.emit("second")
	r.emit("third")
	flush(t, r.journal)
	if !strings.Contains(journal.String(), "third") {
		t.Fatal("console blocked independent journal")
	}
	close(console.release)
	if err = r.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	r = NewReporter(io.Discard, 1)
	r.journal = NewReporter(errorWriter{err: io.ErrClosedPipe}, 1)
	r.emit("event")
	if err = r.Flush(t.Context()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if !errors.Is(r.Err(), io.ErrClosedPipe) {
		t.Fatal("journal error not propagated")
	}
	_ = r.Close(t.Context())
	r = NewReporter(io.Discard, 1)
	r.journal = NewReporter(io.Discard, 1)
	r.journal.dropped.Add(1)
	if err = r.Err(); err == nil || !strings.Contains(err.Error(), "lost 1 journal events") {
		t.Fatal(err)
	}
	_ = r.Close(t.Context())
}
