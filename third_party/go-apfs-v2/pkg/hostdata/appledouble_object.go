package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	sandbox "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/sandbox"
)

type objectMetadata interface {
	heldMetadataOperations
	ClearSourceSecurity() error
}
type objectAttributes interface {
	listSize() (int, error)
	names(int) ([]string, error)
	size(string) (int64, error)
	read(string, []byte) (int, error)
	write(string, []byte) error
	remove(string) error
	truncateFork(uint32) error
	quarantine(context.Context, appledouble.QuarantineProfile) (*appledouble.Quarantine, error)
	applyQuarantine(context.Context, *appledouble.Quarantine, QuarantineProcessCapture, uint32) error
	noSetID() (bool, error)
}

// AppleDoubleObject binds metadata, raw attribute IO, identity resolution and
// captured process policy. It is sequential and caller-owned. Native objects
// never reopen file names; captured objects execute the same policy on any OS.
// Input Value lifetimes remain the caller's responsibility until work finishes.
type AppleDoubleObject struct {
	meta       objectMetadata
	attrs      objectAttributes
	identities *appledouble.ACLIdentityCapture
	process    QuarantineProcessCapture
	sandboxed  bool
	stat       StatCopySource
}

// CapturedAppleDoubleObject supplies complete foreign metadata and source
// identity/process observations. Attribute names must be unique filesystem
// names; AppleDouble record duplication remains a property of the input codec.
// NoSetID nil means uncaptured mount policy and remains an explicit diagnostic.
type CapturedAppleDoubleObject struct {
	State      MetadataState
	Attributes []appledouble.StreamAttr
	// Removals supplies explicit observed provider effects. Unlisted names use
	// logical deletion; this does not claim to reproduce unknown kernel policy.
	Removals []CapturedXattrRemoval
	// Writes binds observed fsetxattr effects to exact input and before bytes.
	Writes     []CapturedXattrWrite
	Identities appledouble.ACLIdentitySnapshot
	Process    QuarantineProcessCapture
	Sandboxed  bool
	NoSetID    *bool
}

// NewCapturedAppleDoubleObject creates a logical destination/source on Linux,
// Windows or macOS. It owns metadata and name tables while borrowing attribute
// Values. New writes own their bytes; resource fork prefix writes borrow an
// unchanged old suffix instead of materializing a potentially large fork.
func NewCapturedAppleDoubleObject(c CapturedAppleDoubleObject) (*AppleDoubleObject, error) {
	meta, err := NewLogicalMetadata(c.State)
	if err != nil {
		return nil, err
	}
	if _, err = c.Process.Process(); err != nil {
		return nil, err
	}
	resolve, lookup, err := c.Identities.Resolvers()
	if err != nil {
		return nil, err
	}
	attrs, err := newLogicalObjectAttributes(meta, c.Attributes, c.NoSetID)
	if err != nil {
		return nil, err
	}
	if err = captureXattrRemovals(attrs, c.Removals); err != nil {
		return nil, err
	}
	if err = captureXattrWrites(attrs, c.Writes); err != nil {
		return nil, err
	}
	c.Process.Agent = bytes.Clone(c.Process.Agent)
	c.Process.Metadata = bytes.Clone(c.Process.Metadata)
	c.Process.Tracking = bytes.Clone(c.Process.Tracking)
	return &AppleDoubleObject{meta: meta, attrs: attrs, identities: appledouble.NewACLIdentityCapture(resolve, lookup), process: c.Process, sandboxed: c.Sandboxed}, nil
}

// NewHostAppleDoubleObject binds a held Darwin file and captures live process
// and directory-service inputs. It does not own or close file. Foreign hosts
// construct NewCapturedAppleDoubleObject from their image/carrier observations.
func NewHostAppleDoubleObject(ctx context.Context, file *os.File) (*AppleDoubleObject, error) {
	return newHostAppleDoubleObject(ctx, file, objectCaptureProviders{
		metadata:   func(f *os.File) (objectMetadata, error) { return NewHeldMetadata(f) },
		identities: aclmeta.NewNativeACLIdentityCapture, process: CaptureQuarantineProcess,
		sandbox: sandbox.CaptureAppSandbox, attributes: newHostObjectAttributes,
	})
}

// Acquisition is composed explicitly so failures can be qualified on every
// host. Native providers still execute for every public host construction.
type objectCaptureProviders struct {
	metadata   func(*os.File) (objectMetadata, error)
	identities func(context.Context) (*appledouble.ACLIdentityCapture, error)
	process    func(context.Context) (*QuarantineProcessCapture, error)
	sandbox    func() (bool, error)
	attributes func(*os.File) (objectAttributes, error)
}

func newHostAppleDoubleObject(ctx context.Context, file *os.File, providers objectCaptureProviders) (*AppleDoubleObject, error) {
	if ctx == nil {
		return nil, os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	meta, err := providers.metadata(file)
	if err != nil {
		return nil, err
	}
	identities, err := providers.identities(ctx)
	if err != nil {
		return nil, err
	}
	process, err := providers.process(ctx)
	if err != nil {
		return nil, err
	}
	sandboxed, err := providers.sandbox()
	if err != nil {
		return nil, err
	}
	attrs, err := providers.attributes(file)
	if err != nil {
		return nil, err
	}
	return &AppleDoubleObject{meta: meta, attrs: attrs, identities: identities, process: *process, sandboxed: sandboxed}, nil
}

// CaptureSecurity acquires the complete native stat/security state in one call.
func (o *AppleDoubleObject) CaptureSecurity() (SecurityCopySource, error) {
	s, st, err := o.meta.CaptureSecurityState()
	o.stat = st
	return s, err
}
func (o *AppleDoubleObject) CaptureStat() (StatCopySource, error) {
	s, err := o.meta.CaptureStat()
	if err == nil {
		o.stat = s
	}
	return s, err
}
func (o *AppleDoubleObject) Chmod(mode uint16) error { return o.meta.Chmod(mode) }
func (o *AppleDoubleObject) DisableCache() error     { return o.meta.DisableCache() }

// IdentitySnapshot records exactly the account observations used by operations.
func (o *AppleDoubleObject) IdentitySnapshot() appledouble.ACLIdentitySnapshot {
	return o.identities.Snapshot()
}

// LogicalSnapshot returns state and borrowed current attributes for an image or
// carrier writer. Native objects require independent native readback instead.
func (o *AppleDoubleObject) LogicalSnapshot() (MetadataState, []appledouble.StreamAttr, error) {
	meta, ok := o.meta.(*LogicalMetadata)
	if !ok {
		return MetadataState{}, nil, errors.ErrUnsupported
	}
	attrs := o.attrs.(*logicalObjectAttributes)
	return meta.Snapshot(), attrs.snapshot(), nil
}

type objectVolumePolicy struct{ source, destination *AppleDoubleObject }

func (p objectVolumePolicy) NoSetID(volume SecurityCopyVolume) (bool, error) {
	if volume == SecurityCopySourceVolume {
		return p.source.attrs.noSetID()
	}
	return p.destination.attrs.noSetID()
}

func (o *AppleDoubleObject) sourceCache(source *SecurityCopySource) func() {
	switch m := o.meta.(type) {
	case *HeldMetadata:
		previous := m.SourceCache
		m.SourceCache = source
		return func() { m.SourceCache = previous }
	case *LogicalMetadata:
		previous := m.SourceCache
		m.SourceCache = source
		return func() { m.SourceCache = previous }
	}
	panic("unregistered AppleDouble object metadata provider")
}

func objectCode(err error) CopyStageResult {
	if err != nil {
		return CopyStageResult{Code: -1, Err: err}
	}
	return CopyStageResult{}
}

// ObjectPackOptions combines native packing with the descriptor outer sequence.
// HasQuarantine is acquired internally; callers must leave that embedded field
// false. Source/target remain open, and output is not implicitly truncated.
type ObjectPackOptions struct {
	PackOptions
	Stat, NoCache bool
	StatOptions   StatCopyOptions
}
type ObjectPackResult struct {
	Lifecycle HeldLifecycleResult
	Pack      PackResult
	Stat      StatCopyResult
}

// PackAppleDoubleObject composes source acquisition, intent/ACL/quarantine
// handling, packing, its final stat and temporary descriptor-mode restoration.
// It executes in pure Go with captured objects on every operating system.
func PackAppleDoubleObject(ctx context.Context, source, destination *AppleDoubleObject, output io.WriterAt, options ObjectPackOptions) (result ObjectPackResult, err error) {
	if ctx == nil || source == nil || destination == nil || output == nil || options.HasQuarantine {
		return result, os.ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	b := objectPackBackend{source: source, destination: destination, output: output, options: options, result: &result}
	result.Lifecycle, err = CopyHeldMetadata(source, destination, HeldLifecycleOptions{Stat: options.Stat, NoCache: options.NoCache}, HeldLifecycleStages{
		CaptureQuarantine: func() error {
			var e error
			b.quarantine, e = source.attrs.quarantine(ctx, source.process.Profile)
			return e
		},
		Run: func(captured SecurityCopySource) CopyStageResult {
			b.security = captured
			opts := options.PackOptions
			opts.HasQuarantine = b.quarantine != nil
			var e error
			result.Pack, e = PackAppleDouble(ctx, opts, &b)
			return CopyStageResult{Code: result.Pack.Code, Err: e}
		},
	})
	return result, err
}

// ObjectUnpackOptions supplies explicit work/allocation budgets and copy policy.
// Sandboxed is acquired from destination; leave the embedded field false.
// Timestamp is queried only for a selected logical quarantine application.
type ObjectUnpackOptions struct {
	UnpackSequentialOptions
	NoCache      bool
	StatOptions  StatCopyOptions
	Timestamp    func() time.Time
	MaxNameBytes uint64
}

// DefaultObjectPackOptions selects explicit 64 MiB active allocation and wire
// format work limits. Native packing's own 16 MiB ordinary policy is unchanged.
func DefaultObjectPackOptions() ObjectPackOptions {
	return ObjectPackOptions{PackOptions: PackOptions{Limits: appledouble.DefaultStreamLimits(), MaxActiveBytes: 64 << 20}}
}

// DefaultObjectUnpackOptions separately bounds destination-name allocation.
func DefaultObjectUnpackOptions() ObjectUnpackOptions {
	return ObjectUnpackOptions{UnpackSequentialOptions: UnpackSequentialOptions{Limits: appledouble.DefaultStreamLimits(), MaxActiveBytes: 64 << 20}, MaxNameBytes: MaxXattrListSize}
}

type ObjectUnpackResult struct {
	Lifecycle HeldLifecycleResult
	Unpack    UnpackResult
	Stat      StatCopyResult
	ACL       aclmeta.ACLRestoreResult
}

// UnpackAppleDoubleObject performs native-order source reads and effects,
// cleanup, ordinary/special records, source-quarantine precedence, deferred ACL,
// final stat and descriptor mode reset. It does not prevalidate the whole input;
// malformed late input may leave earlier changes, exactly as the sequential API.
func UnpackAppleDoubleObject(ctx context.Context, input appledouble.Value, source, destination *AppleDoubleObject, options ObjectUnpackOptions) (result ObjectUnpackResult, err error) {
	if ctx == nil || input == nil || source == nil || destination == nil || options.Sandboxed {
		return result, os.ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	b := objectUnpackBackend{ctx: ctx, source: source, destination: destination, options: options, result: &result, copied: options.InitialCopied}
	result.Lifecycle, err = CopyHeldMetadata(source, destination, HeldLifecycleOptions{Stat: options.Stat, NoCache: options.NoCache}, HeldLifecycleStages{
		CaptureQuarantine: func() error {
			var e error
			b.quarantine, e = source.attrs.quarantine(ctx, source.process.Profile)
			return e
		},
		Run: func(captured SecurityCopySource) CopyStageResult {
			reset := destination.sourceCache(&captured)
			defer reset()
			opts := options.UnpackSequentialOptions
			opts.Sandboxed = destination.sandboxed
			if callback := opts.Callback; callback != nil {
				opts.Callback = func(n UnpackNotice) CopyPipelineAction { b.copied = n.Copied; return callback(n) }
			}
			var e error
			result.Unpack, e = RestoreAppleDoubleSequential(ctx, input, opts, &b)
			return CopyStageResult{Code: result.Unpack.Code, Err: e}
		},
	})
	return result, err
}
