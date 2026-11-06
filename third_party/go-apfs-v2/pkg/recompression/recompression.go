package recompression

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// Volume supplies observed Darwin volume context. Filesystem is
// the native name "apfs" or "hfs", whose timestamp precisions differ. Flags are
// actual mount flags, including MNT_CPROTECT and MNT_NOATIME. The receiving host
// never supplies defaults for this foreign context.
type Volume struct {
	Filesystem string
	Flags      uint32
}

// Options selects foreign-file compression and private staging.
// AllowChangedPayload explicitly accepts intentional edits to a recorded regular
// payload. It updates the association baseline; stale compressed bytes are never
// reused as the edited data. Volume is required even when all flags are zero.
// Clock defaults to time.Now and lets reproducible callers supply operation time.
type Options struct {
	// Target is the explicit macOS product version to reproduce on every host.
	// It never defaults to the receiving host's OS or the newest profile.
	Target osversion.Version
	// Authority supplies captured Darwin credentials, never receiving-host IDs.
	Authority           *Authority
	Volume              *Volume
	Encoding            decmpfs.EncodeOptions
	TemporaryDirectory  string
	AllowChangedPayload bool
	Clock               func() time.Time
}

// Result retains operation outcome separately from publication.
// Published means the new generation was installed. metatransport.Record retains the proposed
// logical state even if publication fails; referenced immutable blobs remain in
// the store. A final publication failure can leave payload changes, as with
// Commit. The old payload baseline then conflicts instead of reactivating stale
// compression storage. Generation advances only after successful publication.
type Result struct {
	Operation  hostdata.RecompressionResult
	Published  bool
	Generation uint64
	Record     metatransport.Record
}

// RecompressRecord recompresses one explicitly associated regular-file record.
// This is an already-resolved, caller-authorized endpoint operation. It does not
// authorize parent traversal or establish that absent source security was observed.
// Pathname callers use RecompressPath with complete explicit source observations;
// they must not fall back here when that context is missing.
// Host access permissions govern access to carrier/payload storage; its Darwin
// metadata is preserved without mapping foreign principals to local identities.
// The caller excludes external payload mutation for the entire operation.
//
// Native operation errors and publication errors are both returned. Accepted in
// Operation alone must never be used to hide publication failure. Cancellation
// before destructive compression stops normally; once virtual data truncation
// occurred, publication completes the retained final state before cancellation
// is reported. Private staging is removed on every path; unreferenced immutable
// blobs retain metatransport.Store's existing publication contract.
func RecompressRecord(ctx context.Context, s *metatransport.Store, name string, expected uint64, options Options) (Result, error) {
	return recompressRecord(ctx, s, name, expected, options, hostdata.Recompress)
}

// carrier keeps storage ownership in metatransport. The compression workflow
// observes held payloads and publishes one generation through this boundary.
type carrier interface {
	Load(context.Context) (metatransport.Manifest, error)
	BorrowRecordAttributes(context.Context, metatransport.Record) (map[string]appledouble.Value, error)
	StoreAttributeValues(context.Context, map[string]appledouble.Value) ([]metatransport.Attribute, error)
	OpenPayload(context.Context, string) (*os.File, error)
	CheckPayload(context.Context, string, interface{ Stat() (os.FileInfo, error) }) error
	Publish(context.Context, metatransport.Manifest, uint64, func() error) (bool, error)
}

type recompressionOperation func(context.Context, func(context.Context) (hostdata.CompressionInput, error), hostdata.RecompressionOptions) (hostdata.RecompressionResult, error)

func recompressRecord(ctx context.Context, s carrier, name string, expected uint64, options Options, operation recompressionOperation) (result Result, err error) {
	profile, e := osversion.ProfileForMacOS(options.Target)
	if e != nil {
		return result, e
	}
	if options.Volume == nil || options.Volume.Filesystem != "apfs" && options.Volume.Filesystem != "hfs" {
		return result, metatransport.ErrInvalid
	}
	manifest, e := s.Load(ctx)
	if e != nil {
		return result, e
	}
	if manifest.Generation != expected {
		return result, metatransport.ErrConflict
	}
	index := -1
	for i, r := range manifest.Records {
		if r.Original == name {
			index = i
			break
		}
	}
	if index < 0 {
		return result, fs.ErrNotExist
	}
	record := manifest.Records[index]
	originalRecord := record
	if record.Kind != "file" || record.MaterializedKind != "file" || record.Darwin.Mode == nil || record.Darwin.Flags == nil || record.Darwin.Modify == nil || record.Darwin.Access == nil || record.Darwin.UID == nil || record.Darwin.GID == nil {
		return result, metatransport.ErrInvalid
	}
	source := hostdata.StatCopySource{Mode: *record.Darwin.Mode, Flags: *record.Darwin.Flags, Times: hostdata.FileTimes{Modify: *record.Darwin.Modify, Access: *record.Darwin.Access}}
	source.UID, source.GID = *record.Darwin.UID, *record.Darwin.GID
	if record.Darwin.Birth != nil {
		source.Times.Birth = *record.Darwin.Birth
	}
	if record.Darwin.Change != nil {
		source.Times.Change = *record.Darwin.Change
	}
	if source.Mode&0170000 != 0100000 {
		return result, metatransport.ErrInvalid
	}
	values, e := s.BorrowRecordAttributes(ctx, record)
	if e != nil {
		return result, e
	}
	var security *appledouble.FileSecurity
	if value := values["com.apple.system.Security"]; value != nil {
		security, e = readRecompressionSecurity(value)
		if e != nil {
			return result, e
		}
	}
	access, e := newRecompressionAccess(record, security, options.Authority, options.Volume.Flags)
	if e != nil {
		return result, e
	}
	access.profile = profile
	data, e := s.OpenPayload(ctx, record.Materialized)
	if e != nil {
		return result, e
	}
	owned := true
	defer func() {
		if owned {
			err = errors.Join(err, data.Close())
		}
	}()
	before, e := metatransport.PayloadReference(ctx, data)
	if e != nil {
		return result, e
	}
	if !options.AllowChangedPayload && before != *record.Payload {
		return result, metatransport.ErrConflict
	}
	directory, e := os.MkdirTemp(options.TemporaryDirectory, "apfs-recompression-")
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, os.RemoveAll(directory)) }()
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	now := func() time.Time {
		v := clock()
		if options.Volume.Filesystem == "hfs" {
			v = v.Truncate(time.Second)
		}
		return v
	}
	object, e := newRecompressionObject(data, source, values, options.Volume.Flags, directory, now)
	if e != nil {
		return result, e
	}
	object.access, object.baseline = access, record.Payload
	owned = false
	defer func() { err = errors.Join(err, object.close()) }()
	result.Operation, err = operation(ctx, object.open, hostdata.RecompressionOptions{Name: path.Base(record.Original), Encoding: options.Encoding, NewStage: func(ctx context.Context) (hostdata.CompressionStage, error) {
		return newRecompressionStage(ctx, directory)
	}})
	if !object.opened {
		return result, err
	}
	publicationContext := ctx
	if object.truncated {
		publicationContext = context.WithoutCancel(ctx)
	}
	attrs, e := object.outputValues()
	if e != nil {
		return result, errors.Join(err, e)
	}
	// Reacquire surviving immutable values after the destructive boundary so
	// cancellation cannot prevent publishing the retained logical state. Values
	// changed by compression keep their new storage; carrier internals stay private.
	if object.truncated && len(object.retained) != 0 {
		retainedRecord := originalRecord
		retainedRecord.Attributes = nil
		retainedRecord.AppleDouble = nil
		for _, attr := range originalRecord.Attributes {
			if object.retained[attr.Name] {
				retainedRecord.Attributes = append(retainedRecord.Attributes, attr)
			}
		}
		fresh, borrowErr := s.BorrowRecordAttributes(publicationContext, retainedRecord)
		if borrowErr != nil {
			return result, errors.Join(err, borrowErr)
		}
		for name, value := range fresh {
			attrs[name] = value
		}
	}
	stored, e := s.StoreAttributeValues(publicationContext, attrs)
	if e != nil {
		return result, errors.Join(err, e)
	}
	state := object.stat()
	record.Attributes, record.AppleDouble = stored, nil
	record.Darwin.Mode, record.Darwin.Flags = &state.Mode, &state.Flags
	record.Darwin.Modify, record.Darwin.Access = &state.Times.Modify, &state.Times.Access
	if object.changeChanged {
		record.Darwin.Change = &state.Times.Change
	}
	record.Payload = &before
	empty := object.truncated && state.Flags&hostdata.UFCompressed == 0
	if empty {
		digest := sha256.Sum256(nil)
		record.Payload = &metatransport.BlobRef{SHA256: hex.EncodeToString(digest[:])}
	}
	result.Record = record
	manifest.Records[index] = record
	// Link-group publication is resolved as one logical inode, never an implicit
	// choice between conflicting aliases. This also refreshes every association.
	aliases, e := recompressionAliases(publicationContext, s, manifest, index, originalRecord, before, record, options.AllowChangedPayload)
	if e != nil {
		return result, errors.Join(err, e)
	}
	defer func() {
		for _, alias := range aliases {
			err = errors.Join(err, alias.Close())
		}
	}()
	transition := func() error {
		return publishRecompressionPayload(publicationContext, s, data, aliases, record, before, empty)
	}
	result.Published, e = s.Publish(publicationContext, manifest, expected, transition)
	if result.Published {
		result.Generation = expected + 1
	}
	return result, errors.Join(err, e, ctx.Err())
}
