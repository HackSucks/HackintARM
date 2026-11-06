package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// carrierName deliberately chooses a name representable on all supported hosts.
// The manifest retains the exact source spelling; real ._ files are ordinary data.
func carrierName(name string, used map[string]bool) string {
	candidate := sanitizeComponentWindows(name)
	for _, r := range candidate {
		if r > 126 {
			candidate = ""
			break
		}
	}
	sum := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(sum[:8])
	if candidate == "" || len(candidate) > 120 {
		candidate = "entry-" + suffix
	}
	base := candidate
	for i := 0; used[strings.ToLower(candidate)]; i++ {
		candidate = base + "-" + suffix + "-" + strconv.Itoa(i)
	}
	used[strings.ToLower(candidate)] = true
	return candidate
}

type carrierExtractEntry struct {
	source string
	info   fs.FileInfo
	record metatransport.Record
}

func (e *Extractor) planCarrier(root, destBase string) ([]carrierExtractEntry, error) {
	var entries []carrierExtractEntry
	mapped := map[string]string{}
	names := map[string]map[string]bool{}
	err := fs.WalkDir(e.Volume, root, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		relative := strings.TrimPrefix(strings.TrimPrefix(name, root), "/")
		if root == "." {
			relative = name
		}
		if relative == "" {
			relative = "."
		}
		original := relative
		if destBase != "" {
			original = path.Join(destBase, relative)
		}
		if e.Pattern != nil && info.Mode().IsRegular() && !e.Pattern.MatchString(relative) {
			return nil
		}
		materialized := "."
		if original != "." {
			parent := path.Dir(original)
			if names[parent] == nil {
				names[parent] = map[string]bool{}
			}
			materialized = path.Join(mapped[parent], carrierName(path.Base(original), names[parent]))
		}
		mapped[original] = materialized
		kind := "file"
		switch {
		case info.IsDir():
			kind = "directory"
		case info.Mode()&fs.ModeSymlink != 0:
			kind = "symlink"
		case !info.Mode().IsRegular():
			return fmt.Errorf("cannot transport special object %q: %w", name, fs.ErrInvalid)
		}
		r := metatransport.Record{Original: original, Materialized: materialized, Kind: kind, MaterializedKind: kind}
		if kind == "symlink" {
			r.Target, err = e.Volume.Readlink(name)
			if err != nil {
				return err
			}
		}
		entries = append(entries, carrierExtractEntry{name, info, r})
		return nil
	})
	return entries, err
}

// extractCarrier publishes the manifest only after every selected entry and
// metadata blob has been written. An empty destination prevents preexisting
// symlink redirection, name collisions and accidental overwrite of user files.
func (e *Extractor) extractCarrier(root, destBase string) (err error) {
	return e.extractCarrierUsing(root, destBase, carrierExtractionOps{os.ReadDir, os.OpenRoot, hostdata.CaptureXattrValuesAt})
}

type carrierExtractionOps struct {
	readDir  func(string) ([]os.DirEntry, error)
	openRoot func(string) (*os.Root, error)
	capture  func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error)
}

func (e *Extractor) extractCarrierUsing(root, destBase string, ops carrierExtractionOps) (err error) {
	e.projectionResults = nil
	ctx := e.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	entries, err := e.planCarrier(root, destBase)
	if err != nil {
		return err
	}
	if e.Xattrs {
		_, byteValues := e.Volume.(XattrVolume)
		_, streamValues := e.Volume.(hostdata.ImageXattrValuesFS)
		if !byteValues && !streamValues {
			return errors.New("source does not expose extended attributes")
		}
	}
	if e.PreserveMeta {
		if _, ok := e.Volume.(hostdata.ImageMetadataFS); !ok {
			return errors.New("source does not expose complete inode metadata")
		}
	}
	if err = os.MkdirAll(e.Destination, 0755); err != nil {
		return err
	}
	existing, err := ops.readDir(e.Destination)
	if err != nil {
		return err
	}
	if len(existing) != 0 {
		return errors.New("metadata transport requires an empty payload destination")
	}
	if err = os.MkdirAll(e.MetadataRoot, 0700); err != nil {
		return err
	}
	limits := metatransport.DefaultLimits()
	if e.MetadataLimits != nil {
		limits = *e.MetadataLimits
	}
	store, err := metatransport.Open(e.Destination, e.MetadataRoot, limits)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	if _, err := store.Load(ctx); !errors.Is(err, fs.ErrNotExist) || errors.Is(err, metatransport.ErrCorrupt) {
		if err == nil {
			return metatransport.ErrConflict
		}
		return err
	}
	payload, err := ops.openRoot(e.Destination)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, payload.Close()) }()
	manifest := metatransport.Manifest{Version: 1}
	carriedCount := 0
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		r := entry.record
		if r.Original != r.Materialized {
			e.namesRemapped++
		}
		if r.Materialized != "." {
			if err = payload.MkdirAll(path.Dir(r.Materialized), 0755); err != nil {
				return err
			}
		}
		switch r.Kind {
		case "directory":
			err = payload.MkdirAll(r.Materialized, 0755)
		case "symlink":
			if e.SymlinkMode != SymlinkFile {
				err = payload.Symlink(r.Target, r.Materialized)
			}
			if e.SymlinkMode == SymlinkFile || (err != nil && e.SymlinkMode == SymlinkAuto) {
				r.MaterializedKind = "file"
				r.Payload, err = writeCarrierPayload(ctx, payload, r.Materialized, io.NopCloser(strings.NewReader(r.Target)))
				e.symlinksDegraded++
			}
			e.filesExtracted++
		case "file":
			var source fs.File
			source, err = e.Volume.Open(entry.source)
			if err == nil {
				r.Payload, err = writeCarrierPayload(ctx, payload, r.Materialized, source)
			}
			if err == nil {
				e.filesExtracted++
				e.bytesExtracted += uint64(r.Payload.Size)
			}
		}
		if err != nil {
			return fmt.Errorf("extract %q: %w", entry.source, err)
		}
		if e.Xattrs {
			attrs, readErr := captureImageValues(e.Volume, entry.source)
			if readErr != nil {
				return readErr
			}
			if r.Kind == "symlink" {
				// APFS exposes its structural target record through Xattrs. The
				// logical link target is already captured independently above.
				attrs = maps.Clone(attrs)
				delete(attrs, "com.apple.fs.symlink")
			}
			// Payload reads decompress the data fork. Preserve the compressed storage
			// in the carrier; the repacker selects it as a unit, never mixes both forms.
			r.Attributes, r.AppleDouble, err = storeCarrierValues(ctx, store, attrs)
			if err != nil {
				return err
			}
			r.SourceAttributesCaptured = true
			carriedCount += len(attrs)
		}
		if e.PreserveMeta {
			m, readErr := e.Volume.(hostdata.ImageMetadataFS).Metadata(entry.source)
			if readErr != nil {
				return readErr
			}
			if !e.Xattrs {
				m.BSDFlags &^= hostdata.UFCompressed
			}
			r.Darwin = metatransport.DarwinState{UID: &m.UID, GID: &m.GID, Mode: &m.Mode, Flags: &m.BSDFlags}
			if m.Times != nil {
				r.Darwin.Birth = &m.Times.Birth
				r.Darwin.Modify = &m.Times.Modify
				r.Darwin.Change = &m.Times.Change
				r.Darwin.Access = &m.Times.Access
			}
			if r.Kind == "file" && m.LinkID != 0 {
				r.LinkGroup = strconv.FormatUint(m.LinkID, 10)
			}
		}
		captureLimits := hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize, ValueBytes: 64 << 20, TotalBytes: 256 << 20}
		if e.NativeCaptureLimits != nil {
			captureLimits = *e.NativeCaptureLimits
		}
		native, captureErr := ops.capture(ctx, payload, filepath.FromSlash(r.Materialized), captureLimits)
		if errors.Is(captureErr, hostdata.ErrXattrUnsupported) {
			r.NativeUnsupported = true
		} else if captureErr != nil {
			return captureErr
		} else {
			r.NativeCaptured = true
			r.NativeAttributes, err = store.StoreAttributeValues(ctx, native)
			if err != nil {
				return err
			}
		}
		if e.VerifyChecksum && r.Payload != nil {
			e.sourceChecksums[filepath.FromSlash(r.Materialized)] = r.Payload.SHA256
		}
		manifest.Records = append(manifest.Records, r)
	}
	if e.ProjectNative {
		captureLimits := hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize, ValueBytes: 64 << 20, TotalBytes: 256 << 20}
		if e.NativeCaptureLimits != nil {
			captureLimits = *e.NativeCaptureLimits
		}
		if err = e.projectCarrier(ctx, payload, store, manifest.Records, captureLimits, newNativeProjection, hostdata.CaptureXattrs, captureProjectionValues); err != nil {
			return err
		}
	}
	if err = store.Commit(ctx, manifest, 0); err != nil {
		return err
	}
	e.xattrsCarried += carriedCount
	return e.projectionError()
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(b)
}

func writeCarrierPayload(ctx context.Context, root *os.Root, name string, source io.ReadCloser) (ref *metatransport.BlobRef, err error) {
	return writeCarrierPayloadUsing(ctx, name, source, func(name string) (carrierPayloadFile, error) {
		return root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	})
}

type carrierPayloadFile interface {
	io.Writer
	Sync() error
	Close() error
}

func writeCarrierPayloadUsing(ctx context.Context, name string, source io.ReadCloser, open func(string) (carrierPayloadFile, error)) (ref *metatransport.BlobRef, err error) {
	defer func() { err = errors.Join(err, source.Close()) }()
	f, err := open(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	digest := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(f, digest), contextReader{ctx, source}, make([]byte, 64<<10))
	if err != nil {
		return nil, err
	}
	if err = f.Sync(); err != nil {
		return nil, err
	}
	return &metatransport.BlobRef{SHA256: hex.EncodeToString(digest.Sum(nil)), Size: n}, ctx.Err()
}

func captureImageValues(volume VolumeFS, name string) (map[string]appledouble.Value, error) {
	if source, ok := volume.(hostdata.ImageXattrValuesFS); ok {
		return source.XattrValues(name)
	}
	attrs, err := volume.(XattrVolume).Xattrs(name)
	if err != nil {
		return nil, err
	}
	return byteAttributeValues(attrs), nil
}

func byteAttributeValues(attrs map[string][]byte) map[string]appledouble.Value {
	values := make(map[string]appledouble.Value, len(attrs))
	for name, value := range attrs {
		values[name] = bytes.NewReader(value)
	}
	return values
}

func storeCarrierAttrs(ctx context.Context, store *metatransport.Store, attrs map[string][]byte) ([]metatransport.Attribute, *metatransport.BlobRef, error) {
	return storeCarrierValues(ctx, store, byteAttributeValues(attrs))
}

func storeCarrierValues(ctx context.Context, store *metatransport.Store, attrs map[string]appledouble.Value) (out []metatransport.Attribute, sidecar *metatransport.BlobRef, err error) {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := attrs[name]
		if value == nil {
			value = bytes.NewReader(nil)
		}
		ref, e := store.PutBlob(ctx, value, value.Size())
		if e != nil {
			return nil, nil, e
		}
		out = append(out, metatransport.Attribute{Name: name, Value: ref})
	}
	if len(attrs) == 0 {
		return out, nil, nil
	}
	// An interoperable sidecar accompanies raw blobs where AppleDouble can
	// represent the namespace. Values outside its wire bounds remain raw blobs.
	stream := appledouble.StreamFile{}
	for _, name := range names {
		value := attrs[name]
		if value == nil {
			value = bytes.NewReader(nil)
		}
		if name == "" || len(name) > 127 || strings.ContainsRune(name, 0) || !utf8.ValidString(name) {
			return out, nil, nil
		}
		switch name {
		case appledouble.FinderInfoName:
			if value.Size() != 32 {
				return out, nil, nil
			}
			n, readErr := value.ReadAt(stream.FinderInfo[:], 0)
			if n != len(stream.FinderInfo) {
				return nil, nil, errors.Join(io.ErrUnexpectedEOF, readErr)
			}
			if readErr != nil && readErr != io.EOF {
				return nil, nil, readErr
			}
		case appledouble.ResourceForkName:
			stream.ResourceFork = value
		default:
			stream.Attrs = append(stream.Attrs, appledouble.StreamAttr{Name: name, Value: value})
		}
	}
	tmp, e := os.CreateTemp("", "apfs-carrier-*.appledouble")
	if e != nil {
		return nil, nil, e
	}
	defer func() { err = errors.Join(err, tmp.Close(), os.Remove(tmp.Name())) }()
	size, e := stream.EncodeTo(ctx, tmp, appledouble.DefaultStreamLimits())
	if e != nil {
		if errors.Is(e, appledouble.ErrTooLarge) {
			return out, nil, nil
		}
		return nil, nil, e
	}
	ref, e := store.PutBlob(ctx, tmp, size)
	if e != nil {
		return nil, nil, e
	}
	return out, &ref, nil
}
