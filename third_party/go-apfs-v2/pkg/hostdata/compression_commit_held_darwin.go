package hostdata

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type heldCompressionCommit struct {
	*HeldMetadata
	file *os.File
}

func newHeldCompressionCommit(file *os.File) (CompressionCommitBackend, error) {
	return newHeldCompressionInstallation(file)
}

func newHeldCompressionInstallation(file *os.File) (CompressionInstallationBackend, error) {
	metadata, err := NewHeldMetadata(file)
	if err != nil {
		return nil, err
	}
	return bindHeldCompressionCommit(file, metadata)
}

func bindHeldCompressionCommit(file *os.File, metadata *HeldMetadata) (*heldCompressionCommit, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fs.ErrInvalid
	}
	return &heldCompressionCommit{metadata, file}, nil
}

func (b *heldCompressionCommit) SetCompressionAttribute(value []byte) error {
	err := SetXattr(b.file, DecmpfsName, value)
	if errors.Is(err, syscall.EACCES) {
		return errors.Join(ErrCompressionAttributeAccess, err)
	}
	return err
}
func (b *heldCompressionCommit) TruncateData(size int64) error { return b.file.Truncate(size) }
func (b *heldCompressionCommit) SyncData() error               { return b.file.Sync() }
func (b *heldCompressionCommit) SetCompressionTimes(modify, access time.Time) error {
	// Avoid UnixNano's int64 year range and NsecToTimeval's upward rounding.
	times := []unix.Timeval{{Sec: access.Unix(), Usec: int32(access.Nanosecond() / 1000)}, {Sec: modify.Unix(), Usec: int32(modify.Nanosecond() / 1000)}}
	return withXattrDescriptor(b.file, func(fd int) error { return unix.Futimes(fd, times) })
}

func (b *heldCompressionCommit) OpenCompressionFork() (CompressionForkWriter, error) {
	return OpenResourceFork(b.file, true)
}
func (b *heldCompressionCommit) CompressionForkSize() (int64, error) {
	var size int
	err := withXattrDescriptor(b.file, func(fd int) error {
		var e error
		size, _, e = visibleXattrSize(func(p []byte) (int, error) { return getCaptureXattrFD(fd, ResourceForkName, p) })
		return e
	})
	return int64(size), err
}
