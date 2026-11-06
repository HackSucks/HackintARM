package cirunner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"time"
)

// jsonObserver buffers at most one 64KiB progress line. Large/binary output is
// retained untouched in the underlying sink, but never copied to console.
type jsonObserver struct {
	writer       io.Writer
	reporter     *Reporter
	label        string
	line         []byte
	discard      bool
	seen         uint64
	emitted      uint64
	last         eventSummary
	lastEmission time.Time
}

type eventSummary struct{ Action, Package, Test, Output string }

func (o *jsonObserver) Write(p []byte) (int, error) {
	n, err := o.writer.Write(p)
	if n > 0 {
		o.observe(p[:n])
	}
	return n, err
}

func (o *jsonObserver) observe(p []byte) {
	for len(p) > 0 {
		end := bytes.IndexByte(p, '\n')
		part := p
		if end >= 0 {
			part = p[:end]
		}
		if len(o.line)+len(part) > 64<<10 {
			o.discard = true
			o.line = o.line[:0]
		}
		if !o.discard {
			o.line = append(o.line, part...)
		}
		if end < 0 {
			return
		}
		if !o.discard {
			o.report()
		}
		o.line = o.line[:0]
		o.discard = false
		p = p[end+1:]
	}
}

func (o *jsonObserver) report() {
	var event eventSummary
	if json.Unmarshal(o.line, &event) != nil {
		return
	}
	switch event.Action {
	case "start", "run", "pause", "cont", "pass", "fail", "skip", "bench", "build-output", "build-fail", "output":
	default:
		return
	}
	if len(event.Output) > 512 {
		event.Output = event.Output[:512] + "... [console excerpt; raw retained]"
	}
	o.seen++
	o.last = event
	// Fast successful tests can produce millions of routine JSON events. They
	// remain complete in the raw sink; console progress is deliberately bounded.
	immediate := o.emitted == 0 || event.Action == "fail" || event.Action == "build-fail" || event.Action == "skip" || (event.Test == "" && (event.Action == "start" || event.Action == "pass"))
	if immediate || time.Since(o.lastEmission) >= time.Second {
		o.flush()
	}
}

func (o *jsonObserver) flush() {
	if o.seen == o.emitted {
		return
	}
	o.reporter.emit(fmt.Sprintf("TEST PROGRESS command=%q events=%d action=%s package=%q test=%q output=%q; routine events coalesced, raw retained", o.label, o.seen, o.last.Action, o.last.Package, o.last.Test, o.last.Output))
	o.emitted = o.seen
	o.lastEmission = time.Now()
}

func sameWriter(a, b io.Writer) bool {
	return a != nil && b != nil && reflect.TypeOf(a).Comparable() && a == b
}

func (c *Cmd) observeOutput() {
	if !c.jsonProgress() || c.Stdout == nil {
		return
	}
	if f, ok := c.Stdout.(*os.File); ok {
		// Keep the actual descriptor: an inherited child handle must not create
		// an os/exec pipe goroutine that makes Wait depend on a descendant.
		c.tailDone = make(chan struct{})
		go func() { defer close(c.tailDone); c.tailErr = c.tail(f) }()
		return
	}
	original := c.Stdout
	observer := &jsonObserver{writer: original, reporter: c.reporter, label: c.label}
	c.observer = observer
	c.Stdout = observer
	if sameWriter(original, c.Stderr) {
		c.Stderr = observer
	}
}

// Regular-file tailing is independent of process creation and the heartbeat.
// Pipes/consoles are already live and are never reopened or converted to pipes.
func (c *Cmd) tail(file *os.File) (result error) {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	reader, err := openObservationFile(file.Name())
	if err != nil {
		c.reporter.emit(fmt.Sprintf("CONSOLE command=%q file progress unavailable: %v; raw sink unchanged", c.label, err))
		return err
	}
	defer func() { result = errors.Join(result, reader.Close()) }()
	opened, err := reader.Stat()
	if err != nil || !os.SameFile(info, opened) {
		c.reporter.emit(fmt.Sprintf("CONSOLE command=%q progress file identity changed; raw sink unchanged", c.label))
		return errors.Join(err, errors.New("cirunner: progress file identity changed"))
	}
	observer := &jsonObserver{reporter: c.reporter, label: c.label}
	defer observer.flush()
	buf := make([]byte, 32<<10)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	finishing := false
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			observer.observe(buf[:n])
		}
		if err != nil && err != io.EOF {
			c.reporter.emit(fmt.Sprintf("CONSOLE command=%q progress read: %v; raw sink unchanged", c.label, err))
			return err
		}
		if n == len(buf) {
			continue
		}
		if finishing && err == io.EOF {
			return nil
		}
		select {
		case <-c.done:
			finishing = true
		case <-ticker.C:
		}
	}
}
