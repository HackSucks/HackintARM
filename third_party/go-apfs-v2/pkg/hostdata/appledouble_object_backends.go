package hostdata

import (
	"context"
	"errors"
	"io"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	xattrintent "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/xattrintent"
)

type objectPackBackend struct {
	source, destination *AppleDoubleObject
	output              io.WriterAt
	options             ObjectPackOptions
	result              *ObjectPackResult
	security            SecurityCopySource
	quarantine          *appledouble.Quarantine
}

func (b *objectPackBackend) ACLPresent() (bool, error) {
	s := b.security.Properties.RawSecurity
	if s == nil {
		return false, nil
	}
	if s.ACL == nil {
		return false, appledouble.ErrFileSecurity
	}
	return true, nil
}
func (b *objectPackBackend) Names(capacity int) ([]string, error) {
	return b.source.attrs.names(capacity)
}
func (b *objectPackBackend) PreserveForIntent(name string, intent uint32) bool {
	return xattrintent.PreserveXattrForIntent(name, intent, b.source.sandboxed)
}
func (b *objectPackBackend) XattrSize(name string) (int64, error) { return b.source.attrs.size(name) }
func (b *objectPackBackend) ReadXattr(name string, dst []byte) (int, error) {
	return b.source.attrs.read(name, dst)
}
func (b *objectPackBackend) ACL() ([]byte, error) {
	s := b.security.Properties.RawSecurity
	if s == nil || s.ACL == nil {
		return nil, appledouble.ErrFileSecurity
	}
	text, err := s.ACL.FormatText(b.source.identities.Lookup)
	if err != nil {
		return nil, err
	}
	return append(text, 0), nil
}
func (b *objectPackBackend) Quarantine() ([]byte, error) {
	return b.quarantine.MarshalBinaryWithProfile(b.source.process.Profile)
}
func (b *objectPackBackend) WriteAt(data []byte, offset int64) (int, error) {
	return b.output.WriteAt(data, offset)
}
func (b *objectPackBackend) Stat() CopyStageResult {
	// copyfile_pack always performs its final stat stage. The outer STAT
	// flag independently controls fcopyfile's subsequent permission reset.
	var err error
	b.result.Stat, err = copyObjectStat(b.source, b.destination, b.options.StatOptions, false)
	return objectCode(err)
}

func copyObjectStat(source, destination *AppleDoubleObject, options StatCopyOptions, invisible bool) (StatCopyResult, error) {
	options.MakeInvisible = options.MakeInvisible || invisible
	if options.VolumePolicy == nil && !options.SourceNoSetID && !options.DestinationNoSetID {
		options.VolumePolicy = objectVolumePolicy{source, destination}
	}
	return CopyStat(source.stat, options, destination.meta)
}

type objectUnpackBackend struct {
	ctx                 context.Context
	source, destination *AppleDoubleObject
	options             ObjectUnpackOptions
	result              *ObjectUnpackResult
	quarantine          *appledouble.Quarantine
	copied              uint64
}

func (b *objectUnpackBackend) ListXattrSize() (int, error) { return b.destination.attrs.listSize() }
func (b *objectUnpackBackend) XattrNames(capacity int) ([]string, error) {
	if capacity < 0 || uint64(capacity) > b.options.MaxNameBytes {
		return nil, errors.Join(ErrUnpackListAllocation, ErrXattrTooLarge)
	}
	return b.destination.attrs.names(capacity)
}
func (b *objectUnpackBackend) RemoveXattr(name string) error { return b.destination.attrs.remove(name) }
func (b *objectUnpackBackend) WriteXattr(name string, value []byte) error {
	return b.destination.attrs.write(name, value)
}
func (b *objectUnpackBackend) CaptureForkState() (UnpackForkState, error) {
	stat, err := b.destination.meta.CaptureStat()
	return UnpackForkState{Directory: stat.Mode&0170000 == 0040000, Times: stat.Times}, err
}
func (b *objectUnpackBackend) RestoreForkTimes(state UnpackForkState) error {
	return b.destination.meta.SetTimes(state.Times.Modify, state.Times.Access)
}
func (b *objectUnpackBackend) ACL(data []byte) CopyStageResult {
	f := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: data}}}
	update, err := f.ACLUpdate(b.source.identities.Resolve)
	if err != nil {
		return objectCode(err)
	}
	b.result.ACL, err = aclmeta.RestoreACL(update, b.destination.meta)
	return objectCode(err)
}
func (b *objectUnpackBackend) Stat(invisible bool) CopyStageResult {
	var err error
	b.result.Stat, err = copyObjectStat(b.source, b.destination, b.options.StatOptions, invisible)
	return objectCode(err)
}
func (b *objectUnpackBackend) Quarantine(data []byte) CopyStageResult {
	q := b.quarantine
	if q == nil {
		var err error
		q, err = appledouble.ParseQuarantineWithProfile(data, b.destination.process.Profile)
		if err != nil {
			return CopyStageResult{Err: err}
		}
	}
	now := time.Now
	if b.options.Timestamp != nil {
		now = b.options.Timestamp
	}
	timestamp := uint32(now().Unix())
	err := b.destination.attrs.applyQuarantine(b.ctx, q, b.destination.process, timestamp)
	if err == nil {
		return CopyStageResult{}
	}
	if b.options.Callback != nil && b.options.Callback(UnpackNotice{Stage: UnpackQuarantine, XattrRestoreNotice: XattrRestoreNotice{Event: XattrRestoreError, Name: appledouble.QuarantineName, Copied: b.copied, WriteError: err}}) != CopyPipelineQuit {
		return CopyStageResult{Err: err}
	}
	code := 45
	var native syscall.Errno
	if errors.As(err, &native) {
		code = int(native)
	} else if errors.Is(err, appledouble.ErrQuarantineMissing) {
		code = 93
	} else if errors.Is(err, appledouble.ErrQuarantineExisting) {
		code = 22
	}
	return CopyStageResult{Code: code, Err: err}
}
