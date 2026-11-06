package hostdata

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type nativeCompressionInput struct {
	file *os.File
	ctx  context.Context
}

func openNativeCompressionInput(ctx context.Context, name string) (CompressionInput, error) {
	return openNativeCompressionInputUsing(ctx, name, os.OpenFile)
}
func openNativeCompressionInputUsing(ctx context.Context, name string, open func(string, int, os.FileMode) (*os.File, error)) (CompressionInput, error) {
	file, err := open(name, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	input, err := NewNativeCompressionInput(ctx, file)
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return input, nil
}

func newNativeCompressionInput(ctx context.Context, file *os.File) (CompressionInput, error) {
	return &nativeCompressionInput{file: file, ctx: ctx}, nil
}
func (b *nativeCompressionInput) Snapshot() (result CompressionFileState, err error) {
	err = withXattrDescriptor(b.file, func(fd int) error {
		var state unix.Stat_t
		if e := unix.Fstat(fd, &state); e != nil {
			return e
		}
		result.Size, result.Stat = state.Size, heldStatMetadata(state)
		return nil
	})
	return result, err
}
func (b *nativeCompressionInput) ProbeWrite() error {
	return withXattrDescriptor(b.file, func(fd int) error { _, err := unix.Write(fd, []byte{}); return err })
}
func (b *nativeCompressionInput) Close() error { return b.file.Close() }
func (b *nativeCompressionInput) Duplicate() (CompressionStream, error) {
	var duplicate int
	err := withXattrDescriptor(b.file, func(fd int) error {
		var e error
		duplicate, e = unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		return e
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), b.file.Name())
	metadata, err := NewHeldMetadata(file)
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return &nativeCompressionStream{heldCompressionCommit: &heldCompressionCommit{HeldMetadata: metadata, file: file}, ctx: b.ctx}, nil
}

type nativeCompressionStream struct {
	*heldCompressionCommit
	ctx context.Context
}

func (b *nativeCompressionStream) ReadAt(p []byte, at int64) (int, error) {
	return b.file.ReadAt(p, at)
}
func (b *nativeCompressionStream) Close() error { return b.file.Close() }
func (b *nativeCompressionStream) VolumeFlags() (uint32, error) {
	return CompressionVolumeFlags(b.ctx, b.file)
}
func (b *nativeCompressionStream) OpenCompressionFork() (CompressionForkWriter, error) {
	// Admission/source stats already captured the data inode. Open relative to its
	// held descriptor; an extra path/stat lookup would introduce a different
	// failure point from the native acquisition sequence.
	var fork *os.File
	err := withXattrDescriptor(b.file, func(fd int) error { var e error; fork, e = openNativeResourceForkContext(b.ctx, fd, true); return e })
	if err != nil {
		return nil, err
	}
	return fork, nil
}
