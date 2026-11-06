package cirunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// FileForwarder mirrors an owned regular file without replacing the child's
// file descriptor with a pipe. Only the worker opens/reads/stats the path or
// writes the destination. It never accesses or closes the caller's descriptor.
// A blocked destination can strand this one worker until Write returns; Stop
// remains bounded, reports incomplete forwarding, and preserves the raw file.
type FileForwarder struct {
	path        string
	destination io.Writer
	stop        chan struct{}
	done        chan struct{}
	once        sync.Once
	err         error // Published by closing done.
}

// ForwardFile begins byte-for-byte forwarding from the beginning of file.
// The caller must own the containing directory and keep the pathname stable;
// the independent descriptor is opened asynchronously. Stop detects pathname
// replacement after that open. Call Stop after the child exits, before removing
// files. Existing output is forwarded too; no text decoding or rewriting occurs.
func ForwardFile(file *os.File, destination io.Writer) *FileForwarder {
	f := &FileForwarder{path: file.Name(), destination: destination, stop: make(chan struct{}), done: make(chan struct{})}
	go f.run()
	return f
}

// Stop requests a final size snapshot in the worker and drains exactly to that
// EOF. A descendant continuing to append cannot extend the requested boundary.
// All filesystem operations stay out of the caller. Repeated Stop calls are safe.
func (f *FileForwarder) Stop(ctx context.Context) error {
	f.once.Do(func() { close(f.stop) })
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return fmt.Errorf("cirunner: forwarding %s incomplete: %w", f.path, ctx.Err())
	}
}

func (f *FileForwarder) run() {
	defer close(f.done)
	reader, err := openObservationFile(f.path)
	if err != nil {
		f.err = err
		return
	}
	defer func() { f.err = errors.Join(f.err, reader.Close()) }()
	info, err := reader.Stat()
	if err != nil {
		f.err = err
		return
	}
	if !info.Mode().IsRegular() {
		f.err = fmt.Errorf("cirunner: forwarding requires a regular file: %s", f.path)
		return
	}
	f.err = f.drain(reader)
	if current, err := os.Stat(f.path); err != nil {
		f.err = errors.Join(f.err, err)
	} else if !os.SameFile(info, current) {
		f.err = errors.Join(f.err, errors.New("cirunner: forwarding source identity changed"))
	}
}

type forwardInput interface {
	io.Reader
	Stat() (os.FileInfo, error)
}

func (f *FileForwarder) drain(reader forwardInput) error {
	var offset int64
	end := int64(-1)
	buf := make([]byte, 32<<10)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if end < 0 {
			select {
			case <-f.stop:
				info, err := reader.Stat()
				if err != nil {
					return err
				}
				end = info.Size()
			default:
			}
		}
		if end >= 0 && offset >= end {
			if offset > end {
				return errors.New("cirunner: forwarding source truncated")
			}
			return nil
		}
		limit := len(buf)
		if end >= 0 && end-offset < int64(limit) {
			limit = int(end - offset)
		}
		n, err := reader.Read(buf[:limit])
		if n > 0 {
			written, writeErr := f.destination.Write(buf[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
			offset += int64(n)
		}
		if err != nil && err != io.EOF {
			return err
		}
		if err == io.EOF && end >= 0 && offset < end {
			return io.ErrUnexpectedEOF
		}
		if n > 0 {
			continue
		}
		select {
		case <-f.stop:
		case <-ticker.C:
		}
	}
}
