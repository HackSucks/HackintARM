package cirunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Options configures console diagnostics, not subprocess I/O or cancellation.
// Set it before starting the command. Zero values select a shared reporter and
// ten-second heartbeats. Go test -json is detected automatically.
type Options struct {
	Reporter     *Reporter
	Label        string
	Heartbeat    time.Duration
	JSONProgress bool
	// FlushTimeout bounds final console/journal drainage; zero selects 500ms.
	FlushTimeout time.Duration
	// StrictReporting (also APFS_CI_STRICT_REPORTING=1) fails commands on lost
	// diagnostics or journal errors, preserving the original error via Join.
	StrictReporting bool
}

// Cmd embeds exec.Cmd so environments, files, pipes, process attributes, Cancel
// and WaitDelay retain their ordinary semantics. Like exec.Cmd, it is single-use.
// The raw command is unexported so lifecycle methods cannot be bypassed.
type rawCmd = exec.Cmd

type Cmd struct {
	*rawCmd
	Options        Options
	ctx            context.Context
	reporter       *Reporter
	label          string
	done           chan struct{}
	monitorDone    chan struct{}
	tailDone       chan struct{}
	tailErr        error
	observer       *jsonObserver
	pid            atomic.Int64
	cancelReported atomic.Bool
	started        time.Time
}

// Command is exec.Command with live diagnostics and a background context.
func Command(name string, args ...string) *Cmd {
	return &Cmd{rawCmd: exec.Command(name, args...), ctx: context.Background()}
}

// CommandContext preserves exec.CommandContext cancellation and panic semantics.
func CommandContext(ctx context.Context, name string, args ...string) *Cmd {
	return &Cmd{rawCmd: exec.CommandContext(ctx, name, args...), ctx: ctx}
}

func (c *Cmd) begin() {
	if c.done != nil {
		return
	}
	c.reporter = c.Options.Reporter
	if c.reporter == nil {
		c.reporter = DefaultReporter()
	}
	c.label = c.Options.Label
	if c.label == "" {
		c.label = strings.Join(c.Args, " ")
	}
	c.started = time.Now()
	c.done = make(chan struct{})
	c.monitorDone = make(chan struct{})
	c.reporter.emit(fmt.Sprintf("START command=%q; monitoring process startup", c.label))
	interval := c.Options.Heartbeat
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go c.monitor(interval)
}

func (c *Cmd) monitor(interval time.Duration) {
	defer close(c.monitorDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	cancelled := c.ctx.Done()
	for {
		select {
		case <-c.done:
			return
		case <-cancelled:
			c.reportCancellation()
			cancelled = nil
		case <-ticker.C:
			c.reporter.emit(fmt.Sprintf("ACTIVITY command=%q pid=%d elapsed=%s; no test progress inferred", c.label, c.pid.Load(), time.Since(c.started).Round(time.Millisecond)))
		}
	}
}

func (c *Cmd) finish(err error) error {
	if c.observer != nil {
		c.observer.flush()
	}
	if c.ctx.Err() != nil {
		c.reportCancellation()
	}
	close(c.done)
	<-c.monitorDone // The monitor never does console or filesystem I/O.
	c.reporter.emit(fmt.Sprintf("FINISH command=%q elapsed=%s error=%v context=%v console_dropped=%d console_error=%v", c.label, time.Since(c.started).Round(time.Millisecond), err, c.ctx.Err(), c.reporter.Dropped(), c.reporter.Err()))
	timeout := c.Options.FlushTimeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.ctx), timeout)
	defer cancel()
	var reportErr error
	if c.tailDone != nil {
		select {
		case <-c.tailDone:
			reportErr = c.tailErr
		case <-ctx.Done():
			reportErr = fmt.Errorf("cirunner: progress file drain incomplete: %w", ctx.Err())
		}
	}
	if reportErr != nil {
		c.reporter.emit(fmt.Sprintf("REPORT_ERROR command=%q error=%v; raw sink unchanged", c.label, reportErr))
	}
	reportErr = errors.Join(reportErr, c.reporter.Flush(ctx))
	if c.Options.StrictReporting || os.Getenv("APFS_CI_STRICT_REPORTING") == "1" {
		if dropped := c.reporter.Dropped(); dropped != 0 {
			reportErr = errors.Join(reportErr, fmt.Errorf("cirunner: lost %d console diagnostics", dropped))
		}
		if reportErr != nil {
			return errors.Join(err, fmt.Errorf("cirunner: reporting incomplete: %w", reportErr))
		}
	}
	return err
}

func (c *Cmd) reportCancellation() {
	if c.cancelReported.CompareAndSwap(false, true) {
		c.reporter.emit(fmt.Sprintf("CANCEL command=%q context=%v; awaiting process exit", c.label, c.ctx.Err()))
	}
}

// Start starts diagnostics before process creation, including failed starts.
func (c *Cmd) Start() error {
	if c.done != nil {
		return c.rawCmd.Start()
	}
	c.begin()
	c.observeOutput()
	err := c.rawCmd.Start()
	if err != nil {
		return c.finish(err)
	}
	c.pid.Store(int64(c.Process.Pid))
	c.reporter.emit(fmt.Sprintf("LAUNCHED command=%q pid=%d", c.label, c.pid.Load()))
	return nil
}

// Wait preserves exec.Wait semantics. Cancellation is reported independently,
// before Wait returns even if a kernel operation delays process termination.
func (c *Cmd) Wait() error {
	if c.done == nil {
		return c.rawCmd.Wait()
	}
	err := c.rawCmd.Wait()
	select {
	case <-c.done:
	default:
		err = c.finish(err)
	}
	return err
}

// Run is Start followed by Wait.
func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

// Output preserves exec.Output's bytes, error type, and bounded stderr excerpt.
func (c *Cmd) Output() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	var out bytes.Buffer
	c.Stdout = &out
	capture := c.Stderr == nil
	var stderr excerpt
	if capture {
		c.Stderr = &stderr
	}
	err := c.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && capture {
		exit.Stderr = stderr.bytes()
	}
	return out.Bytes(), err
}

// CombinedOutput preserves exec.CombinedOutput's single combined output sink.
func (c *Cmd) CombinedOutput() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	if c.Stderr != nil {
		return nil, errors.New("exec: Stderr already set")
	}
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	return out.Bytes(), err
}

func (c *Cmd) jsonProgress() bool {
	if c.Options.JSONProgress {
		return true
	}
	if strings.TrimSuffix(filepath.Base(c.Path), ".exe") != "go" {
		return false
	}
	args := c.Args[1:]
	if len(args) >= 2 && args[0] == "tool" && args[1] == "test2json" {
		return true
	}
	if len(args) == 0 || args[0] != "test" {
		return false
	}
	for _, arg := range args[1:] {
		if arg == "-json" || arg == "-json=true" {
			return true
		}
	}
	return false
}

// excerpt retains the same 32KiB prefix/suffix and omission text as exec.Output.
type excerpt struct {
	first, last []byte
	total       int64
}

func (w *excerpt) Write(p []byte) (int, error) {
	n := len(p)
	w.total += int64(n)
	if len(w.first) < 32<<10 {
		keep := min(len(p), (32<<10)-len(w.first))
		w.first = append(w.first, p[:keep]...)
		p = p[keep:]
	}
	if len(p) >= 32<<10 {
		w.last = append(w.last[:0], p[len(p)-(32<<10):]...)
	} else {
		if len(w.last)+len(p) > 32<<10 {
			w.last = append(w.last[:0], w.last[len(w.last)+len(p)-(32<<10):]...)
		}
		w.last = append(w.last, p...)
	}
	return n, nil
}
func (w *excerpt) bytes() []byte {
	out := append([]byte(nil), w.first...)
	if omitted := w.total - int64(len(w.first)+len(w.last)); omitted > 0 {
		out = fmt.Appendf(out, "\n... omitting %d bytes ...\n", omitted)
	}
	return append(out, w.last...)
}
