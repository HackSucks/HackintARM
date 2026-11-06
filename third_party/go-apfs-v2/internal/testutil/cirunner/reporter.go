// Package cirunner adds bounded, live CI diagnostics to os/exec commands.
// Raw command output remains owned by the caller; diagnostic loss never changes
// command bytes or errors. It does not change process-tree or signal semantics.
package cirunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type message struct {
	text string
	ack  chan struct{}
}

// Reporter serializes console writes outside subprocess and heartbeat goroutines.
// Its bounded queue drops console messages under backpressure, never raw output.
// A writer blocked inside Write cannot be interrupted by portable Go; Close and
// Flush still honor their contexts, and only one worker can block per Reporter.
type Reporter struct {
	writer  io.Writer
	queue   chan message
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	dropped atomic.Uint64
	mu      sync.Mutex
	err     error
	journal *Reporter
}

// NewReporter starts one worker. Call Close with a bounded context when finished.
// A nil writer selects os.Stderr. Capacity must be positive; zero selects 256.
func NewReporter(writer io.Writer, capacity int) *Reporter {
	if writer == nil {
		writer = os.Stderr
	}
	if capacity <= 0 {
		capacity = 256
	}
	r := &Reporter{writer: writer, queue: make(chan message, capacity), stop: make(chan struct{}), done: make(chan struct{})}
	go r.run()
	return r
}

var defaultOnce sync.Once
var defaultReporter *Reporter

// DefaultReporter is shared by commands without an explicit reporter. Programs
// should Flush it before exiting; keep it open while other commands can start.
func DefaultReporter() *Reporter {
	defaultOnce.Do(func() {
		defaultReporter = NewReporter(os.Stderr, 256)
		if dir := os.Getenv("APFS_CI_REPORT_DIR"); dir != "" {
			defaultReporter.journal = NewReporter(&journalWriter{directory: dir}, 1024)
		}
	})
	return defaultReporter
}

// Dropped counts console messages lost to backpressure or a closed reporter.
func (r *Reporter) Dropped() uint64 { return r.dropped.Load() }

// Err returns the first console write failure. Raw command sinks are independent.
func (r *Reporter) Err() error {
	r.mu.Lock()
	err := r.err
	r.mu.Unlock()
	if r.journal != nil {
		err = errors.Join(err, r.journal.Err())
		if n := r.journal.Dropped(); n > 0 {
			err = errors.Join(err, fmt.Errorf("cirunner: lost %d journal events", n))
		}
	}
	return err
}

func (r *Reporter) emit(text string) {
	if r.journal != nil {
		r.journal.emit(text)
	}
	select {
	case <-r.stop:
		r.dropped.Add(1)
		return
	default:
	}
	select {
	case r.queue <- message{text: text}:
	default:
		r.dropped.Add(1)
	}
}

func (r *Reporter) write(s string) {
	n, err := io.WriteString(r.writer, s)
	if err == nil && n != len(s) {
		err = io.ErrShortWrite
	}
	if err != nil {
		r.mu.Lock()
		if r.err == nil {
			r.err = err
		}
		r.mu.Unlock()
	}
}

func (r *Reporter) run() {
	defer close(r.done)
	if j, ok := r.writer.(*journalWriter); ok {
		defer func() {
			if err := j.close(); err != nil {
				r.mu.Lock()
				r.err = errors.Join(r.err, err)
				r.mu.Unlock()
			}
		}()
	}
	var reported uint64
	for {
		select {
		case <-r.stop:
			return
		case m := <-r.queue:
			if dropped := r.Dropped(); dropped > reported {
				r.write(fmt.Sprintf("CI console diagnostics dropped=%d; raw command evidence remains in caller sinks\n", dropped))
				reported = dropped
			}
			if m.text != "" {
				r.write(m.text + "\n")
			}
			if m.ack != nil {
				close(m.ack)
			}
		}
	}
}

// Flush waits for previously queued console messages, bounded by ctx. It also
// reports any console writer error; callers must retain/report that distinction.
func (r *Reporter) Flush(ctx context.Context) error {
	if r.journal != nil {
		if err := r.journal.Flush(ctx); err != nil {
			return err
		}
	}
	ack := make(chan struct{})
	select {
	case <-r.stop:
		return errors.Join(errors.New("cirunner: reporter closed"), r.Err())
	case <-ctx.Done():
		return ctx.Err()
	case r.queue <- message{ack: ack}:
	}
	select {
	case <-ack:
		return r.Err()
	case <-r.done:
		return errors.Join(errors.New("cirunner: reporter closed"), r.Err())
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close flushes then stops the worker, without waiting beyond ctx. Repeated calls
// are safe. An uninterruptible writer may outlive this call until Write returns.
func (r *Reporter) Close(ctx context.Context) error {
	err := r.Flush(ctx)
	r.once.Do(func() { close(r.stop) })
	if r.journal != nil {
		err = errors.Join(err, r.journal.Close(ctx))
	}
	select {
	case <-r.done:
		return errors.Join(err, r.Err())
	case <-ctx.Done():
		return errors.Join(err, ctx.Err())
	}
}

// Journal setup and disk writes run only in the journal worker. A blocked
// filesystem cannot stop command startup, heartbeat generation or cancellation.
// Each process owns its file; original child output remains in caller sinks.
type journalWriter struct {
	directory string
	file      *os.File
}

func (j *journalWriter) Write(p []byte) (int, error) {
	if j.file == nil {
		if err := os.MkdirAll(j.directory, 0755); err != nil {
			return 0, err
		}
		f, err := os.CreateTemp(j.directory, fmt.Sprintf("commands-%d-*.jsonl", os.Getpid()))
		if err != nil {
			return 0, err
		}
		j.file = f
	}
	data, err := json.Marshal(struct {
		Time    time.Time `json:"time"`
		Message string    `json:"message"`
	}{time.Now().UTC(), string(p)})
	if err != nil {
		return 0, err
	}
	if _, err = j.file.Write(append(data, '\n')); err != nil {
		return 0, fmt.Errorf("write CI journal %s: %w", filepath.Base(j.file.Name()), err)
	}
	return len(p), nil
}
func (j *journalWriter) close() error {
	if j.file != nil {
		return j.file.Close()
	}
	return nil
}
