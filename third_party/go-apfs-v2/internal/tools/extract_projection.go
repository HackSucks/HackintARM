package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/internal/unixmode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// ProjectionStatus describes native materialization, independently of the
// complete logical state retained in the carrier.
type ProjectionStatus string

const (
	// ProjectionApplied means a native write succeeded. Verified distinguishes
	// exact readback from the native call's success alone.
	ProjectionApplied ProjectionStatus = "applied"
	// ProjectionRetained means the selected state remains in the carrier because
	// the host, allocation budget or payload representation cannot project it.
	ProjectionRetained ProjectionStatus = "retained"
	// ProjectionNormalized means a native write succeeded but exact readback differs.
	ProjectionNormalized ProjectionStatus = "normalized"
	// ProjectionFailed retains an unexpected native failure; extraction returns it
	// after publishing the complete carrier whenever publication succeeds.
	ProjectionFailed ProjectionStatus = "failed"
)

// ProjectionResult records one selected native operation. Err retains its cause;
// carrier preservation does not imply that native permissions were enforced.
type ProjectionResult struct {
	Path, Field string
	Status      ProjectionStatus
	Verified    bool
	Err         error
}

// NativeProjectionResults returns an independent report in execution order.
func (e *Extractor) NativeProjectionResults() []ProjectionResult {
	return append([]ProjectionResult(nil), e.projectionResults...)
}

type projectionBackend interface {
	SetXattr(string, []byte) error
	Security(*appledouble.FileSecurity) error
	Chown(uint32, uint32) error
	Chmod(uint16) error
	SetTimes(time.Time, time.Time) error
	SetBirth(time.Time) error
	Chflags(uint32) error
}
type projectionMetadata interface {
	WriteSecurity(aclmeta.DarwinChmodArguments) error
	Chflags(uint32) error
	CaptureStat() (hostdata.StatCopySource, error)
	CaptureACL() (aclmeta.ACLMetadata, error)
	SetTimes(time.Time, time.Time) error
}

type nativeProjection struct {
	file    *os.File
	held    projectionMetadata
	heldErr error
	symlink bool
}

func newNativeProjection(f *os.File) projectionBackend {
	h, err := hostdata.NewHeldMetadata(f)
	info, statErr := f.Stat()
	isLink := statErr == nil && info.Mode()&os.ModeSymlink != 0
	return nativeProjection{file: f, held: h, heldErr: errors.Join(err, statErr), symlink: isLink}
}
func (p nativeProjection) SetXattr(n string, v []byte) error {
	return p.nativeError(hostdata.SetXattr(p.file, n, v))
}
func (p nativeProjection) Security(s *appledouble.FileSecurity) error {
	if p.heldErr != nil {
		return p.heldErr
	}
	a, err := (aclmeta.DarwinChmodProperties{RawSecurity: s, OwnerUUID: &s.OwnerUUID, GroupUUID: &s.GroupUUID}).ChmodArguments()
	if err != nil {
		return err
	}
	return p.held.WriteSecurity(a)
}
func (p nativeProjection) Chown(u, g uint32) error {
	if uint64(u) > uint64(^uint(0)>>1) || uint64(g) > uint64(^uint(0)>>1) {
		return os.ErrInvalid
	}
	err := p.file.Chown(int(u), int(g))
	if err != nil && runtime.GOOS == "windows" {
		return errors.Join(errors.ErrUnsupported, err)
	}
	return p.nativeError(err)
}
func (p nativeProjection) Chmod(m uint16) error {
	return p.nativeError(p.file.Chmod(unixmode.FilePermissions(m)))
}
func (p nativeProjection) SetTimes(m, a time.Time) error {
	if p.heldErr == nil {
		return p.held.SetTimes(m, a)
	}
	return p.nativeError(hostdata.SetFileTimes(p.file, m, a))
}
func (p nativeProjection) SetBirth(t time.Time) error { return hostdata.SetCreationTime(p.file, t) }
func (p nativeProjection) Chflags(f uint32) error {
	if p.heldErr != nil {
		return p.heldErr
	}
	return p.held.Chflags(f)
}

func projectionConstraint(err error) bool {
	return errors.Is(err, errors.ErrUnsupported) || errors.Is(err, hostdata.ErrXattrUnsupported) || errors.Is(err, hostdata.ErrXattrTooLarge) || errors.Is(err, hostdata.ErrCreationTimeUnsupported) || errors.Is(err, hostdata.ErrFileTimesUnsupported) || errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrInvalid) || errors.Is(err, syscall.E2BIG) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, appledouble.ErrFileSecurity)
}
func (e *Extractor) projection(path, field string, err error) {
	state := ProjectionApplied
	if err != nil {
		state = ProjectionFailed
		if projectionConstraint(err) {
			state = ProjectionRetained
		}
	}
	e.projectionResults = append(e.projectionResults, ProjectionResult{Path: path, Field: field, Status: state, Err: err})
}
func projectionBytes(ctx context.Context, v appledouble.Value, max int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v == nil || v.Size() < 0 {
		return nil, fs.ErrInvalid
	}
	if v.Size() > int64(max) {
		return nil, hostdata.ErrXattrTooLarge
	}
	p := make([]byte, int(v.Size()))
	n, err := v.ReadAt(p, 0)
	if n != len(p) {
		return nil, errors.Join(io.ErrUnexpectedEOF, err)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return p, ctx.Err()
}

// applyProjection executes selected writes while logical source values remain
// unchanged in the carrier. The backend must refer to one held destination.
func (e *Extractor) applyProjection(ctx context.Context, r metatransport.Record, attrs map[string]appledouble.Value, max int, b projectionBackend) error {
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	compression, compressed := attrs[hostdata.DecmpfsName]
	if r.Darwin.Flags != nil {
		compressed = compressed && *r.Darwin.Flags&hostdata.UFCompressed != 0
	}
	forkBacked := false
	if compressed {
		var shapeErr error
		forkBacked, shapeErr = decmpfs.UsesResourceFork(compression)
		if shapeErr != nil {
			forkBacked = true
			e.projection(r.Original, "compression-shape", errors.Join(fs.ErrInvalid, shapeErr))
		}
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if compressed && (name == hostdata.DecmpfsName || (name == hostdata.ResourceForkName && forkBacked)) {
			e.projection(r.Original, "xattr:"+name, fmt.Errorf("payload is decompressed: %w", errors.ErrUnsupported))
			continue
		}
		if name == hostdata.ResourceForkName {
			if writer, ok := b.(projectionForkWriter); ok {
				e.projection(r.Original, "xattr:"+name, writer.ResourceFork(ctx, attrs[name], max))
				continue
			}
		}
		value, err := projectionBytes(ctx, attrs[name], max)
		if err == nil {
			if name == hostdata.SecurityName {
				var security *appledouble.FileSecurity
				security, err = appledouble.ParseFileSecurity(value)
				if err == nil {
					err = b.Security(security)
				}
			} else {
				err = b.SetXattr(name, value)
			}
		}
		e.projection(r.Original, "xattr:"+name, err)
	}
	d := r.Darwin
	if d.UID != nil && d.GID != nil {
		e.projection(r.Original, "ownership", b.Chown(*d.UID, *d.GID))
	}
	if d.Mode != nil {
		e.projection(r.Original, "mode", b.Chmod(uint16(*d.Mode&07777)))
	}
	if d.Modify != nil && d.Access != nil {
		err := b.SetTimes(*d.Modify, *d.Access)
		e.projection(r.Original, "modify", err)
		e.projection(r.Original, "access", err)
	}
	if d.Birth != nil {
		e.projection(r.Original, "birth", b.SetBirth(*d.Birth))
	}
	if d.Change != nil {
		e.projection(r.Original, "change", fmt.Errorf("native change time is kernel-controlled: %w", errors.ErrUnsupported))
	}
	if d.Flags != nil {
		flags := *d.Flags
		if flags&hostdata.UFCompressed != 0 {
			flags &^= hostdata.UFCompressed
			e.projection(r.Original, "flags:compressed", fmt.Errorf("payload is decompressed: %w", errors.ErrUnsupported))
		}
		e.projection(r.Original, "flags", b.Chflags(flags))
	}
	return ctx.Err()
}

func (e *Extractor) verifyProjection(r metatransport.Record, native map[string][]byte) {
	for i := range e.projectionResults {
		result := &e.projectionResults[i]
		if result.Path != r.Original || result.Status != ProjectionApplied {
			continue
		}
		for _, a := range r.Attributes {
			if result.Field != "xattr:"+a.Name {
				continue
			}
			value, present := native[a.Name]
			sum := sha256.Sum256(value)
			if !present || hex.EncodeToString(sum[:]) != a.Value.SHA256 || int64(len(value)) != a.Value.Size {
				result.Status = ProjectionNormalized
			} else {
				result.Verified = true
			}
		}
	}
}

func (e *Extractor) projectCarrier(ctx context.Context, payload *os.Root, store *metatransport.Store, records []metatransport.Record, limits hostdata.XattrCaptureLimits, makeBackend func(*os.File) projectionBackend, capture func(context.Context, *os.File, hostdata.XattrCaptureLimits) (map[string][]byte, error), captureValues ...func(context.Context, *os.Root, string, *os.File, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error)) error {
	for i := len(records) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := &records[i]
		if r.Kind == "symlink" && r.MaterializedKind != "symlink" {
			e.projection(r.Original, "symlink-metadata", fmt.Errorf("degraded symlink requires its logical carrier: %w", errors.ErrUnsupported))
			continue
		}
		f, err := hostdata.OpenMetadataFile(payload, filepath.FromSlash(r.Materialized))
		if err != nil {
			e.projection(r.Original, "open", err)
			continue
		}
		attrs, err := store.BorrowRecordAttributes(ctx, *r)
		backend := makeBackend(f)
		if err == nil {
			err = e.applyProjection(ctx, *r, attrs, limits.ValueBytes, backend)
		}
		if err != nil {
			return errors.Join(err, f.Close())
		}
		var native map[string][]byte
		var nativeValues map[string]appledouble.Value
		var captureErr error
		if len(captureValues) > 0 {
			nativeValues, captureErr = captureValues[0](ctx, payload, filepath.FromSlash(r.Materialized), f, limits)
		} else {
			native, captureErr = capture(ctx, f, limits)
		}
		switch {
		case errors.Is(captureErr, hostdata.ErrXattrUnsupported):
			if !r.NativeCaptured {
				r.NativeUnsupported = true
			}
			e.projection(r.Original, "native-baseline", captureErr)
		case captureErr != nil:
			e.projection(r.Original, "native-baseline", captureErr)
		default:
			var baseline []metatransport.Attribute
			if len(captureValues) > 0 {
				baseline, err = store.StoreAttributeValues(ctx, nativeValues)
			} else {
				baseline, err = store.StoreAttributes(ctx, native)
			}
			if err != nil {
				return errors.Join(err, f.Close())
			}
			r.NativeAttributes, r.NativeCaptured, r.NativeUnsupported = baseline, true, false
			e.verifyProjectionRefs(*r, r.NativeAttributes)
		}
		if reader, ok := backend.(projectionReadback); ok {
			checks, readErr := reader.Readback(*r)
			if readErr != nil {
				e.projection(r.Original, "native-readback", readErr)
			} else {
				e.verifyProjectionChecks(*r, checks)
			}
		}
		if err = f.Close(); err != nil {
			e.projection(r.Original, "close", err)
		}
	}
	return nil
}
func (e *Extractor) projectionError() error {
	var err error
	for _, r := range e.projectionResults {
		if r.Status == ProjectionFailed {
			err = errors.Join(err, fmt.Errorf("native projection %q %s: %w", r.Path, r.Field, r.Err))
		}
	}
	return err
}

func (p nativeProjection) nativeError(err error) error {
	if p.symlink && runtime.GOOS == "linux" && errors.Is(err, syscall.EBADF) {
		return errors.Join(errors.ErrUnsupported, err)
	}
	return err
}

type projectionForkWriter interface {
	ResourceFork(context.Context, appledouble.Value, int) error
}

func (p nativeProjection) ResourceFork(ctx context.Context, value appledouble.Value, max int) error {
	_, err := hostdata.ReplaceResourceFork(ctx, p.file, value)
	if !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if runtime.GOOS == "windows" {
		max = min(max, 65535)
	}
	data, err := projectionBytes(ctx, value, max)
	if err != nil {
		return err
	}
	return p.SetXattr(hostdata.ResourceForkName, data)
}
func (e *Extractor) verifyProjectionRefs(r metatransport.Record, native []metatransport.Attribute) {
	refs := make(map[string]metatransport.BlobRef, len(native))
	for _, a := range native {
		refs[a.Name] = a.Value
	}
	for i := range e.projectionResults {
		result := &e.projectionResults[i]
		if result.Path != r.Original || result.Status != ProjectionApplied {
			continue
		}
		for _, a := range r.Attributes {
			if result.Field == "xattr:"+a.Name {
				got, present := refs[a.Name]
				result.Verified = present && got == a.Value
				if !result.Verified {
					result.Status = ProjectionNormalized
				}
			}
		}
	}
}
