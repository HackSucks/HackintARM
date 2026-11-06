package hostdata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// PathAppleDoubleOperation selects one complete path operation.
type PathAppleDoubleOperation uint8

const (
	PathPackAppleDouble PathAppleDoubleOperation = iota + 1
	PathUnpackAppleDouble
)

// CapturedPathProtection records an observed mount capability and file class.
// Nil observations are unknown, not a negative capability result.
type CapturedPathProtection struct {
	Supported bool
	Class     int
}

// CapturedPathCreation supplies source-system creation context. ParentACL and
// Umask determine inheritance; State supplies captured creator ownership and
// timestamps. Process/identity policy comes from Template. No receiving-host
// account or process state is substituted for these inputs.
type CapturedPathCreation struct {
	Template  CapturedAppleDoubleObject
	ParentACL *appledouble.ACL
	Umask     uint16
}

// CapturedPathContext executes logical Darwin metadata operations while the
// receiving host opens and transfers actual file contents. Source and an
// existing Destination are operation-owned objects; creation requires Creation.
// The context receives a newly created Destination and updated protection class.
// Preserve its logical snapshot in an image/carrier before releasing borrowed
// input Values. Native ACL enforcement is not inferred from a logical update.
type CapturedPathContext struct {
	Source, Destination                     *AppleDoubleObject
	Creation                                *CapturedPathCreation
	RealUserUUID, EffectiveUserUUID         *[16]byte
	SourceProtection, DestinationProtection *CapturedPathProtection
}

// AppleDoublePathOptions combines path acquisition with one existing native-
// style pack/unpack policy. Zero open budget is invalid. Captured is required
// for logical Darwin operation on foreign hosts; nil uses live Darwin providers.
// NoFollow selects final links; intermediate paths retain normal OS resolution.
// Callers exclude concurrent path/content/metadata mutation for this operation.
type AppleDoublePathOptions struct {
	Operation                                PathAppleDoubleOperation
	Pack                                     ObjectPackOptions
	Unpack                                   ObjectUnpackOptions
	Exclusive, UnlinkDestination, MoveSource bool
	NoFollowSource, NoFollowDestination      bool
	DontSetProtection                        bool
	MaxOpenAttempts                          uint64
	Captured                                 *CapturedPathContext
}

// AppleDoublePathResult preserves the complete outer trace and selected inner
// result. A failure may leave metadata changes, a truncated file, or a removed
// pack destination. No rollback or implicit fsync is promised.
type AppleDoublePathResult struct {
	Lifecycle PathLifecycleResult
	Pack      PackResult
	Unpack    UnpackResult
	Stat      StatCopyResult
	ACL       aclmeta.ACLRestoreResult
}

// CopyAppleDoublePath opens/creates, runs the selected AppleDouble operation,
// restores measured temporary permissions and closes every owned descriptor.
// Source and destination are ordinary explicit OS paths. Logical capture makes
// the same policy available on Linux/Windows without invoking macOS tools.
// Close failures remain errors even when the native route itself succeeded.
func CopyAppleDoublePath(ctx context.Context, source, destination string, options AppleDoublePathOptions) (result AppleDoublePathResult, err error) {
	return copyAppleDoublePath(ctx, source, destination, options, defaultPathNativeOps())
}

// The operation boundary is explicit so failures before/after native effects
// can be tested on every host; live Darwin providers are independently replayed
// against the retained C corpus.
type pathNativeOps struct {
	supported    bool
	heldMeta     func(*os.File) (objectMetadata, error)
	capture      func(string, bool) (PathMetadata, error)
	bind         func(context.Context, *os.File) (*AppleDoubleObject, error)
	identities   func(context.Context) (*appledouble.ACLIdentityCapture, error)
	singleWriter func(*os.File) error
	protection   func(*os.File) (bool, error)
	getClass     func(*os.File) (int, error)
	setClass     func(*os.File, int) error
	identity     func(os.FileInfo) (LinkIdentity, bool)
}

func defaultPathNativeOps() pathNativeOps {
	return pathNativeOps{runtime.GOOS == "darwin", func(f *os.File) (objectMetadata, error) { return NewHeldMetadata(f) }, CapturePathMetadata,
		NewHostAppleDoubleObject, aclmeta.NewNativeACLIdentityCapture,
		pathSingleWriter, FileProtectionSupport, ReadProtectionClass, SetProtectionClass, Link}
}

func copyAppleDoublePath(ctx context.Context, source, destination string, options AppleDoublePathOptions, native pathNativeOps) (result AppleDoublePathResult, err error) {
	result.Lifecycle.Code = -1
	if ctx == nil || source == "" || destination == "" || options.MaxOpenAttempts == 0 || (options.Operation != PathPackAppleDouble && options.Operation != PathUnpackAppleDouble) {
		return result, os.ErrInvalid
	}
	if options.Captured == nil && !native.supported {
		return result, errors.ErrUnsupported
	}
	if options.Captured != nil && options.Captured.Source == nil {
		return result, os.ErrInvalid
	}
	if c := options.Captured; c != nil && (c.RealUserUUID == nil || c.EffectiveUserUUID == nil) {
		return result, appledouble.ErrACLIdentityUncaptured
	}
	if (options.Operation == PathPackAppleDouble && options.Pack.HasQuarantine) || (options.Operation == PathUnpackAppleDouble && options.Unpack.Sandboxed) {
		return result, os.ErrInvalid
	}
	binding := appleDoublePath{ctx: ctx, sourceName: source, destinationName: destination, options: options, result: &result, native: native, access: defaultPathAccessOps()}
	stat := options.Pack.Stat
	if options.Operation == PathUnpackAppleDouble {
		stat = options.Unpack.Stat
	}
	result.Lifecycle, err = CopyPathMetadata(ctx, PathLifecycleOptions{Stat: stat, Exclusive: options.Exclusive, MoveSource: options.MoveSource, UnlinkDestination: options.UnlinkDestination, MaxOpenAttempts: options.MaxOpenAttempts}, &binding)
	return result, err
}

type appleDoublePath struct {
	ctx                         context.Context
	sourceName, destinationName string
	options                     AppleDoublePathOptions
	result                      *AppleDoublePathResult
	sourceFile, destinationFile *os.File
	source, destination         *AppleDoubleObject
	sourceMetadata              PathMetadata
	destinationObservation      PathDestinationState
	destinationMetadata         PathMetadata
	temporaryFile               *os.File
	temporaryMeta               objectMetadata
	quarantine                  *appledouble.Quarantine
	native                      pathNativeOps
	access                      pathAccessOps
	backing                     pathBackingAccess
	forkAccess                  pathForkAccess
	sourceFork, destinationFork io.Closer
}

func (p *appleDoublePath) SameObject() (bool, error) {
	a, e := os.Stat(p.sourceName)
	if e != nil {
		return false, e
	}
	b, e := os.Stat(p.destinationName)
	if e != nil {
		return false, e
	}
	return os.SameFile(a, b), nil
}

func (p *appleDoublePath) capture(name string, source, nofollow bool) (PathMetadata, error) {
	if p.options.Captured == nil {
		return p.native.capture(name, nofollow)
	}
	stat := os.Stat
	if nofollow {
		stat = os.Lstat
	}
	info, err := stat(name)
	if err != nil {
		return PathMetadata{}, err
	}
	object := p.options.Captured.Destination
	if source {
		object = p.options.Captured.Source
	}
	if object == nil {
		return PathMetadata{}, fmt.Errorf("missing captured path object: %w", os.ErrInvalid)
	}
	security, state, err := object.meta.CaptureSecurityState()
	identity, _ := p.native.identity(info)
	return PathMetadata{State: MetadataState{Security: security, Stat: state}, Identity: identity, Size: info.Size()}, err
}

func (p *appleDoublePath) CaptureDestination() (PathDestinationState, error) {
	nofollow := p.options.NoFollowDestination
	if !nofollow && p.options.NoFollowSource {
		if info, e := p.access.info(p.sourceName, true); e == nil && info.Mode()&os.ModeSymlink != 0 {
			nofollow = true
		}
	}
	captured, e := p.capture(p.destinationName, false, nofollow)
	p.destinationMetadata = captured
	p.destinationObservation = PathDestinationState{Stat: captured.State.Stat, Properties: captured.State.Security.Properties, NoFollowLink: captured.State.Stat.Mode&0170000 == 0120000}
	return p.destinationObservation, e
}

func (p *appleDoublePath) RealUserUUID() ([16]byte, error) {
	if c := p.options.Captured; c != nil {
		if c.RealUserUUID == nil {
			return [16]byte{}, appledouble.ErrACLIdentityUncaptured
		}
		return *c.RealUserUUID, nil
	}
	identities, e := p.native.identities(p.ctx)
	if e != nil {
		return [16]byte{}, e
	}
	uid := uint32(os.Getuid())
	return identities.Resolve(appledouble.ACLIdentity{ID: &uid})
}

func (p *appleDoublePath) ApplyTemporarySecurity(properties aclmeta.DarwinChmodProperties) error {
	arguments, err := properties.ChmodArguments()
	if err != nil {
		return err
	}
	if c := p.options.Captured; c != nil {
		if c.Destination == nil {
			return os.ErrInvalid
		}
		if err = p.prepareBackingAccess(); err != nil {
			return err
		}
		p.temporaryMeta = c.Destination.meta
	} else {
		p.temporaryFile, err = p.access.open(p.destinationName, os.O_RDONLY, 0, p.destinationObservation.NoFollowLink || p.options.NoFollowDestination, false, 0)
		if err != nil {
			return err
		}
		info, e := p.temporaryFile.Stat()
		if e != nil {
			return e
		}
		identity, ok := p.native.identity(info)
		if !ok || identity.Device != p.destinationMetadata.Identity.Device || identity.Inode != p.destinationMetadata.Identity.Inode || pathModeType(info.Mode()) != p.destinationObservation.Stat.Mode&0170000 {
			return errors.Join(ErrMetadataIdentity, syscall.EBADF)
		}
		p.temporaryMeta, err = p.native.heldMeta(p.temporaryFile)
		if err != nil {
			return err
		}
	}
	err = p.temporaryMeta.WriteSecurity(arguments)
	if errors.Is(err, errors.ErrUnsupported) || errors.Is(err, syscall.ENOTSUP) {
		return p.temporaryMeta.Chmod(uint16(p.destinationObservation.Stat.Mode&07777) | 0200)
	}
	return err
}

// ValidateDestination mirrors the second identity comparison, after the payload
// descriptor is opened but before cache configuration or route effects.
func (p *appleDoublePath) ValidateDestination() error {
	saved := p.temporaryFile
	if saved == nil {
		saved = p.backing.file
	}
	if saved == nil {
		return nil
	}
	original, err := saved.Stat()
	if err != nil {
		return err
	}
	current, err := p.destinationFile.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(original, current) || original.Mode().Type() != current.Mode().Type() {
		return errors.Join(ErrMetadataIdentity, syscall.EBADF)
	}
	return nil
}

func (p *appleDoublePath) CloseTemporarySecurity() []HeldLifecycleStep {
	p.temporaryMeta = nil
	steps := p.closeBackingAccess()
	if p.temporaryFile == nil {
		return steps
	}
	file := p.temporaryFile
	p.temporaryFile = nil
	return append(steps, HeldLifecycleStep{Operation: "close-temporary-security", Err: file.Close()})
}

func pathModeType(mode os.FileMode) uint32 {
	if mode&os.ModeCharDevice != 0 {
		return 0020000
	}
	if mode&os.ModeSymlink != 0 {
		return 0120000
	}
	if mode.IsDir() {
		return 0040000
	}
	if mode.IsRegular() {
		return 0100000
	}
	return 0
}

func (p *appleDoublePath) ConfigureIO() []HeldLifecycleStep {
	steps := []HeldLifecycleStep{{Operation: "source-no-cache", Err: p.source.DisableCache()}, {Operation: "destination-no-cache", Err: p.destination.DisableCache()}}
	if p.options.Captured == nil {
		steps = append(steps, HeldLifecycleStep{Operation: "destination-single-writer", Err: p.native.singleWriter(p.destinationFile)})
	}
	return steps
}

func (p *appleDoublePath) Run(ctx context.Context) (CopyStageResult, []HeldLifecycleStep) {
	if p.options.Operation == PathPackAppleDouble {
		var objectResult ObjectPackResult
		options := p.options.Pack
		options.HasQuarantine = p.quarantine != nil
		backend := objectPackBackend{source: p.source, destination: p.destination, output: p.destinationFile, options: options, result: &objectResult, security: p.sourceMetadata.State.Security, quarantine: p.quarantine}
		var err error
		p.result.Pack, err = PackAppleDouble(ctx, options.PackOptions, &backend)
		p.result.Stat = objectResult.Stat
		var steps []HeldLifecycleStep
		if p.result.Pack.Code < 0 {
			steps = append(steps, HeldLifecycleStep{Operation: "remove-destination", Err: pathUnlink(p.destinationName)})
		}
		return CopyStageResult{Code: p.result.Pack.Code, Err: err}, steps
	}
	info, err := p.sourceFile.Stat()
	if err != nil {
		return objectCode(err), nil
	}
	value := pathInputValue{File: p.sourceFile, length: info.Size()}
	var objectResult ObjectUnpackResult
	options := p.options.Unpack
	options.Sandboxed = p.destination.sandboxed
	backend := objectUnpackBackend{ctx: ctx, source: p.source, destination: p.destination, options: options, result: &objectResult, quarantine: p.quarantine, copied: options.InitialCopied}
	if callback := options.Callback; callback != nil {
		options.Callback = func(notice UnpackNotice) CopyPipelineAction { backend.copied = notice.Copied; return callback(notice) }
	}
	cache := p.sourceMetadata.State.Security
	restore := p.destination.sourceCache(&cache)
	defer restore()
	p.result.Unpack, err = RestoreAppleDoubleSequential(ctx, value, options.UnpackSequentialOptions, &backend)
	p.result.Stat, p.result.ACL = objectResult.Stat, objectResult.ACL
	code := p.result.Unpack.Code
	if code < 0 {
		code = -1
	}
	return CopyStageResult{Code: code, Err: err}, nil
}

func (p *appleDoublePath) RestoreBSD(stat StatCopySource, failure bool) []HeldLifecycleStep {
	prefix := "held-"
	var meta objectMetadata
	if p.destination != nil {
		meta = p.destination.meta
	}
	if failure && p.temporaryMeta != nil {
		prefix = "temporary-"
		meta = p.temporaryMeta
	}
	if meta == nil && p.options.Captured != nil && p.options.Captured.Destination != nil {
		meta = p.options.Captured.Destination.meta
	}
	owner, mode := error(syscall.EBADF), error(syscall.EBADF)
	if meta != nil {
		owner = meta.Chown(stat.UID, stat.GID)
		mode = meta.Chmod(uint16(stat.Mode))
	}
	return []HeldLifecycleStep{{Operation: prefix + "owner", Err: owner}, {Operation: prefix + "mode", Err: mode}}
}

func (p *appleDoublePath) ResetSecurity() []HeldLifecycleStep {
	object := p.destination
	stat := p.options.Pack.Stat
	if p.options.Operation == PathUnpackAppleDouble {
		stat = p.options.Unpack.Stat
	}
	if stat {
		object = p.source
	}
	state, err := object.CaptureStat()
	steps := []HeldLifecycleStep{{Operation: "reset-stat", Err: err}}
	if err != nil {
		return append(steps, HeldLifecycleStep{Operation: "reset-security", Err: ErrPathLifecycleUndefined})
	}
	var effective [16]byte
	if c := p.options.Captured; c != nil {
		if c.EffectiveUserUUID == nil {
			return append(steps, HeldLifecycleStep{Operation: "effective-user", Err: appledouble.ErrACLIdentityUncaptured})
		}
		effective = *c.EffectiveUserUUID
	} else {
		// Restoration must finish even if cancellation arrives after the route's
		// final check. Preserve caller values for identity lookup, but do not let
		// a canceled deadline leave the temporary access ACE on the destination.
		identities, e := p.native.identities(context.WithoutCancel(p.ctx))
		if e != nil {
			return append(steps, HeldLifecycleStep{Operation: "effective-user", Err: e})
		}
		uid := uint32(os.Geteuid())
		effective, e = identities.Resolve(appledouble.ACLIdentity{ID: &uid})
		if e != nil {
			return append(steps, HeldLifecycleStep{Operation: "effective-user", Err: e})
		}
	}
	reset, _ := ResetPathSecurity(p.destination.meta, uint16(state.Mode), effective)
	return append(steps, reset.Steps...)
}
func (p *appleDoublePath) RemoveSource() error { return os.Remove(p.sourceName) }
func (p *appleDoublePath) Close() []HeldLifecycleStep {
	steps := p.CloseTemporarySecurity()
	if p.sourceFile != nil {
		steps = append(steps, HeldLifecycleStep{Operation: "close-source", Err: p.sourceFile.Close()})
		p.sourceFile = nil
	}
	steps = append(steps, p.closeSourceFork()...)
	if p.destinationFile != nil {
		steps = append(steps, HeldLifecycleStep{Operation: "close-destination", Err: p.destinationFile.Close()})
		p.destinationFile = nil
	}
	steps = append(steps, p.closeDestinationFork()...)
	return steps
}
