// Package imagefile provides a temporary-file-backed io.WriterAt for building
// a raw file system image without holding it in memory.
//
// The writers emit an image through an io.WriterAt, and until now the command
// line handed them a bytes.Buffer. That made peak memory proportional to the
// image: building a 15 GB volume needed 15 GB of RAM, and more than that in
// practice, because sizing the image writes its final byte and so forces the
// buffer to its full length in one allocation.
package imagefile

import (
	"fmt"
	"os"
	"sync"
)

// File is a scratch file satisfying io.WriterAt and io.ReaderAt.
//
// Writers that size an image by writing its final byte — which is what
// pkg/apfswrite does — create a sparse file, so the space actually consumed is
// the space actually written, not the image's nominal size. That holds on APFS,
// HFS+, ext4, XFS and Btrfs. NTFS does not make a file sparse without an
// explicit FSCTL, so on Windows the scratch file really does occupy its full
// size on disk; that is disk rather than memory, which is the trade being made.
type File struct {
	file *os.File
	path string

	mu   sync.Mutex
	high int64 // one past the highest byte offset written
	done bool
}

// New creates a scratch file in dir and returns it. An empty dir uses the
// system temporary directory.
//
// Prefer a directory on the same file system as the eventual output. The system
// temporary directory is often small, and on many Linux images it is tmpfs —
// backed by RAM — so spilling a large image there would reproduce the very
// problem this type exists to avoid.
//
// The caller must Close the returned File, which closes and removes it.
func New(dir, pattern string) (*File, error) {
	if pattern == "" {
		pattern = "image-*.tmp"
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, fmt.Errorf("imagefile: create scratch file: %w", err)
	}
	return &File{file: f, path: f.Name()}, nil
}

// WriteAt implements io.WriterAt.
func (f *File) WriteAt(p []byte, off int64) (int, error) {
	n, err := f.file.WriteAt(p, off)
	if n > 0 {
		f.mu.Lock()
		if end := off + int64(n); end > f.high {
			f.high = end
		}
		f.mu.Unlock()
	}
	return n, err
}

// ReadAt implements io.ReaderAt, so the finished image can be handed straight
// to the DMG encoder without being read back into memory.
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	return f.file.ReadAt(p, off)
}

// Size returns one past the highest offset written: the image's length.
//
// This is tracked rather than taken from the file's stat size so it is correct
// even for a writer that never writes the final byte, and so it matches what
// the in-memory buffer this replaced would have reported.
func (f *File) Size() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.high
}

// Name returns the scratch file's path, for diagnostics.
func (f *File) Name() string { return f.path }

// Close closes the file and removes it. It is safe to call more than once, so a
// deferred Close can sit alongside an explicit one.
//
// The file is closed before being removed because Windows refuses to unlink a
// file that is still open.
func (f *File) Close() error {
	f.mu.Lock()
	if f.done {
		f.mu.Unlock()
		return nil
	}
	f.done = true
	f.mu.Unlock()

	closeErr := f.file.Close()
	removeErr := os.Remove(f.path)
	if closeErr != nil {
		return closeErr
	}
	if removeErr != nil && !os.IsNotExist(removeErr) {
		return removeErr
	}
	return nil
}
