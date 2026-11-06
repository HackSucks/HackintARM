package recompression

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"

	internal "github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// recompressionObject is a private foreign inode view. Its materialized payload
// remains logical data while the protocol changes ordinary/compressed storage.
// Publication applies the final view, including an empty ordinary fork after a
// failed activation. Neither host BSD flags nor host identity define this view.
// The operation owns the object; protocol input/stream handles are scoped leases.
type recompressionObject struct {
	access        *recompressionAccess
	baseline      *metatransport.BlobRef
	change        time.Time
	changeChanged bool
	data          *os.File
	metadata      *hostdata.LogicalMetadata
	values        map[string]appledouble.Value
	retained      map[string]bool
	volume        uint32
	now           func() time.Time
	directory     string
	forkFile      *os.File
	readers       []*os.File
	truncated     bool
	closed        bool
	opened        bool
}

func newRecompressionObject(data *os.File, source hostdata.StatCopySource, values map[string]appledouble.Value, volume uint32, directory string, now func() time.Time) (*recompressionObject, error) {
	if data == nil || now == nil {
		return nil, metatransport.ErrInvalid
	}
	metadata, e := hostdata.NewLogicalMetadata(hostdata.MetadataState{Stat: source, Security: hostdata.SecurityCopySource{UID: source.UID, GID: source.GID, Mode: source.Mode}})
	if e != nil {
		return nil, e
	}
	copied := make(map[string]appledouble.Value, len(values))
	retained := make(map[string]bool, len(values))
	for name, value := range values {
		if value == nil || value.Size() < 0 {
			return nil, metatransport.ErrInvalid
		}
		copied[name] = value
		retained[name] = true
	}
	return &recompressionObject{data: data, metadata: metadata, values: copied, retained: retained, volume: volume, now: now, directory: directory, change: source.Times.Change}, nil
}

func (o *recompressionObject) open(ctx context.Context) (hostdata.CompressionInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.closed || o.opened {
		return nil, metatransport.ErrInvalid
	}
	if e := o.authorize("open-data"); e != nil {
		return nil, e
	}
	// A write-open materializes active compression but preserves an independent
	// fork accompanying inline storage. Inactive opaque metadata remains opaque.
	flags, _ := o.metadata.ReadFlags()
	if flags&hostdata.UFCompressed != 0 {
		fork, e := internal.UsesResourceFork(o.values[hostdata.DecmpfsName])
		if e != nil {
			return nil, e
		}
		// Genuine macOS 15 and 26 O_RDWR observations reject active LZ4 storage
		// with ENOTSUP before any inode transition. The portable decoder still
		// supports those bytes; this is versioned operation policy, not a codec gap.
		if o.access != nil && (o.access.profile == osversion.MacOS15 || o.access.profile == osversion.MacOS26) {
			var kind [4]byte
			n, readErr := o.values[hostdata.DecmpfsName].ReadAt(kind[:], 4)
			if n != len(kind) || readErr != nil && !errors.Is(readErr, io.EOF) {
				return nil, errors.Join(io.ErrUnexpectedEOF, readErr)
			}
			if value := binary.LittleEndian.Uint32(kind[:]); value == 15 || value == 16 {
				return nil, syscall.ENOTSUP
			}
		}
		if o.baseline != nil {
			if e := validateRecompressionStorage(ctx, o.values, *o.baseline); e != nil {
				return nil, e
			}
		}
		delete(o.values, hostdata.DecmpfsName)
		delete(o.retained, hostdata.DecmpfsName)
		if fork {
			delete(o.values, hostdata.ResourceForkName)
			delete(o.retained, hostdata.ResourceForkName)
		}
		_ = o.metadata.Chflags(flags &^ hostdata.UFCompressed)
		source, _ := o.metadata.CaptureStat()
		_ = o.metadata.SetTimes(o.now(), source.Times.Access)
		o.changed()
	}
	o.opened = true
	return &recompressionInput{object: o}, nil
}
func (o *recompressionObject) close() error {
	if o.closed {
		return nil
	}
	o.closed = true
	var errs []error
	if o.forkFile != nil {
		errs = append(errs, o.forkFile.Close())
	}
	for _, file := range o.readers {
		errs = append(errs, file.Close())
	}
	errs = append(errs, o.data.Close())
	return errors.Join(errs...)
}
func (o *recompressionObject) outputValues() (map[string]appledouble.Value, error) {
	if o.closed {
		return nil, os.ErrClosed
	}
	path := filepath.Join(o.directory, "resource-fork")
	file, e := os.Open(path)
	if e == nil {
		info, err := file.Stat()
		if err != nil {
			return nil, errors.Join(err, file.Close())
		}
		o.readers = append(o.readers, file)
		if info.Size() > 0 {
			o.values[hostdata.ResourceForkName] = io.NewSectionReader(file, 0, info.Size())
			delete(o.retained, hostdata.ResourceForkName)
		} else {
			delete(o.values, hostdata.ResourceForkName)
			delete(o.retained, hostdata.ResourceForkName)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	values := make(map[string]appledouble.Value, len(o.values))
	for name, value := range o.values {
		values[name] = value
	}
	return values, nil
}

type recompressionInput struct {
	object *recompressionObject
	closed bool
}

func (i *recompressionInput) ready() error {
	if i.closed || i.object.closed {
		return os.ErrClosed
	}
	return nil
}
func (i *recompressionInput) Snapshot() (hostdata.CompressionFileState, error) {
	if e := i.ready(); e != nil {
		return hostdata.CompressionFileState{}, e
	}
	info, e := i.object.data.Stat()
	if e != nil {
		return hostdata.CompressionFileState{}, e
	}
	return hostdata.CompressionFileState{Size: info.Size(), Stat: i.object.stat()}, nil
}
func (i *recompressionInput) ProbeWrite() error { return i.ready() }
func (i *recompressionInput) Duplicate() (hostdata.CompressionStream, error) {
	if e := i.ready(); e != nil {
		return nil, e
	}
	return &recompressionStream{recompressionInput: recompressionInput{object: i.object}}, nil
}
func (i *recompressionInput) Close() error {
	if i.closed {
		return os.ErrClosed
	}
	i.closed = true
	return nil
}

type recompressionStream struct{ recompressionInput }

func (s *recompressionStream) ReadAt(p []byte, at int64) (int, error) {
	if e := s.ready(); e != nil {
		return 0, e
	}
	n, err := s.object.data.ReadAt(p, at)
	if n > 0 && s.object.volume&0x10000000 == 0 {
		state, _ := s.object.metadata.CaptureStat()
		_ = s.object.metadata.SetTimes(state.Times.Modify, s.object.now())
	}
	return n, err
}
func (s *recompressionStream) VolumeFlags() (uint32, error) { return s.object.volume, s.ready() }
func (s *recompressionStream) ReadFlags() (uint32, error) {
	if e := s.ready(); e != nil {
		return 0, e
	}
	return s.object.metadata.ReadFlags()
}
func (s *recompressionStream) CompareAndSwapFlags(a, b uint32) (uint32, error) {
	if e := s.ready(); e != nil {
		return 0, e
	}
	if e := s.object.authorize("flags"); e != nil {
		return 0, e
	}
	actual, e := s.object.metadata.CompareAndSwapFlags(a, b)
	if e == nil && actual == a {
		s.object.changed()
	}
	return actual, e
}
func (s *recompressionStream) SetCompressionAttribute(p []byte) error {
	if e := s.ready(); e != nil {
		return e
	}
	if e := s.object.authorize("attribute"); e != nil {
		if errors.Is(e, syscall.EACCES) {
			return errors.Join(e, hostdata.ErrCompressionAttributeAccess)
		}
		return e
	}
	s.object.changed()
	s.object.values[hostdata.DecmpfsName] = bytes.NewReader(bytes.Clone(p))
	delete(s.object.retained, hostdata.DecmpfsName)
	return nil
}
func (s *recompressionStream) Chmod(mode uint16) error {
	if e := s.ready(); e != nil {
		return e
	}
	if s.object.access != nil {
		if e := s.object.access.chmod(s.object.stat(), mode); e != nil {
			return e
		}
	}
	s.object.changed()
	return s.object.metadata.Chmod(mode)
}
func (s *recompressionStream) TruncateData(size int64) error {
	if e := s.ready(); e != nil {
		return e
	}
	if size != 0 {
		return metatransport.ErrInvalid
	}
	if e := s.object.authorize("truncate"); e != nil {
		return e
	}
	stat := s.object.stat()
	_ = s.object.metadata.SetTimes(s.object.now(), stat.Times.Access)
	s.object.changed()
	s.object.truncated = true
	return nil
}
func (s *recompressionStream) SyncData() error {
	if e := s.ready(); e != nil {
		return e
	}
	return s.object.data.Sync()
}
func (s *recompressionStream) SetCompressionTimes(modify, access time.Time) error {
	if e := s.ready(); e != nil {
		return e
	}
	if e := s.object.authorize("times"); e != nil {
		return e
	}
	s.object.changed()
	return s.object.metadata.SetTimes(modify, access)
}
func (s *recompressionStream) CompressionForkSize() (int64, error) {
	if e := s.ready(); e != nil {
		return 0, e
	}
	if value := s.object.values[hostdata.ResourceForkName]; value != nil {
		return value.Size(), nil
	}
	return 0, nil
}
func (s *recompressionStream) OpenCompressionFork() (hostdata.CompressionForkWriter, error) {
	if e := s.ready(); e != nil {
		return nil, e
	}
	if e := s.object.authorize("open-fork"); e != nil {
		return nil, e
	}
	return &recompressionFork{object: s.object}, nil
}

type recompressionFork struct {
	object *recompressionObject
	closed bool
}

func (f *recompressionFork) WriteAt(p []byte, at int64) (int, error) {
	if f.closed || f.object.closed {
		return 0, os.ErrClosed
	}
	if f.object.forkFile == nil {
		file, e := os.OpenFile(filepath.Join(f.object.directory, "resource-fork"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return 0, e
		}
		f.object.forkFile = file
	}
	n, err := f.object.forkFile.WriteAt(p, at)
	if n > 0 {
		f.object.changed()
	}
	return n, err
}
func (f *recompressionFork) Sync() error {
	if f.closed || f.object.closed {
		return os.ErrClosed
	}
	if f.object.forkFile == nil {
		return nil
	}
	return f.object.forkFile.Sync()
}
func (f *recompressionFork) Close() error {
	if f.closed {
		return os.ErrClosed
	}
	f.closed = true
	if f.object.forkFile == nil {
		return nil
	}
	e := f.object.forkFile.Close()
	f.object.forkFile = nil
	return e
}

type recompressionStage struct{ *os.File }

func (s recompressionStage) Close() error { return errors.Join(s.File.Close(), os.Remove(s.Name())) }
func newRecompressionStage(ctx context.Context, directory string) (hostdata.CompressionStage, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	file, e := os.CreateTemp(directory, "encoded-")
	if e != nil {
		return nil, e
	}
	return recompressionStage{file}, nil
}

func (o *recompressionObject) stat() hostdata.StatCopySource {
	state, _ := o.metadata.CaptureStat()
	state.Times.Change = o.change
	return state
}
func (o *recompressionObject) changed() { o.change = o.now(); o.changeChanged = true }
func (o *recompressionObject) authorize(operation string) error {
	if o.access == nil {
		return nil
	}
	return o.access.authorize(operation, o.stat())
}
