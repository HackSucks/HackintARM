package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// ErrXattrNotFound identifies the native ENOATTR namespace result. In
// particular, listing an existing but invalid AppleDouble file can return it;
// that is distinct from listing an absent sidecar's empty namespace.
var ErrXattrNotFound = errors.New("filesystem extended attribute not found")

type filesystemMetadataOps struct {
	list    func(*os.File, int) ([]string, error)
	read    func(*os.File, string, int) ([]byte, bool, error)
	size    func(*os.File, string) (int, bool, error)
	fork    func(*os.File, bool) (*os.File, error)
	sidecar func(*os.Root, string) (*os.File, error)
	writer  func(*os.Root, string) (*os.File, error)
	unlink  func(*os.Root, string) error
	remove  func(context.Context, appledouble.AttributeFile, string) (appledouble.AttributeRemoval, error)
}

func defaultFilesystemMetadataOps() filesystemMetadataOps {
	return filesystemMetadataOps{list: ListXattrNames, read: ReadXattr, size: XattrSize, fork: OpenResourceFork, sidecar: openFilesystemSidecar,
		writer: openFilesystemMetadataWriter, unlink: func(root *os.Root, name string) error { return root.Remove(name) }, remove: appledouble.RemoveFilesystemAttribute}
}

// FilesystemMetadata binds attribute discovery to an entry and its containing
// directory. Darwin uses its native filesystem dispatch. Linux and Windows FAT
// volumes resolve Apple's dot-underscore storage; other filesystems use native
// attributes and never reinterpret neighboring files as metadata.
//
// Close releases only the handles owned by this view. Values returned by OpenValue
// have independent Close ownership. Exclude concurrent namespace and metadata
// mutation; identity checks detect substitution, not arbitrary same-size writes.
// The view provides no snapshot transaction or automatic metadata migration.
type FilesystemMetadata struct {
	ops      filesystemMetadataOps
	mu       sync.Mutex
	file     *os.File
	parent   *os.Root
	name     string
	identity os.FileInfo
	sidecar  bool
	closed   bool
	borrowed bool
}

// OpenFilesystemMetadata acquires the named entry without following its final
// symlink. Parent traversal stays inside root. No sidecar setting is required.
// The returned view owns independent handles; root remains caller-owned.
// name must identify an entry beneath root, with a nonempty final component
// other than dot or dot-dot. To inspect a directory, pass its name and parent
// root; its AppleDouble association lives in that parent, not inside it.
func OpenFilesystemMetadata(ctx context.Context, root *os.Root, name string) (*FilesystemMetadata, error) {
	return openFilesystemMetadata(ctx, root, name, filesystemUsesAppleDouble)
}

func openFilesystemMetadata(ctx context.Context, root *os.Root, name string, selectStorage func(*os.File) (bool, error)) (*FilesystemMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if root == nil || !filepath.IsLocal(name) {
		return nil, os.ErrInvalid
	}
	parent, base := filepath.Split(name)
	if base == "" || base == "." || base == ".." {
		return nil, os.ErrInvalid
	}
	if parent == "" {
		parent = "."
	}
	dir, err := root.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	file, err := OpenMetadataFileRead(dir, base)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	v := &FilesystemMetadata{file: file, parent: dir, name: base, ops: defaultFilesystemMetadataOps()}
	v.identity, err = file.Stat()
	if err == nil {
		v.sidecar, err = selectStorage(file)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, errors.Join(err, v.Close())
	}
	return v, nil
}

func (v *FilesystemMetadata) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.closed {
		return os.ErrClosed
	}
	return nil
}

// Close is idempotent, including after an earlier close error.
func (v *FilesystemMetadata) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	var err error
	if !v.borrowed {
		err = v.file.Close()
	}
	if v.parent != nil {
		err = errors.Join(err, v.parent.Close())
	}
	return err
}

// List returns visible names in native storage order, with a bounded combined
// name length (including NUL terminators). Missing AppleDouble storage is empty;
// permission, I/O and unqualified format errors are not converted to absence.
func (v *FilesystemMetadata) List(ctx context.Context, maxBytes int) (names []string, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(ctx); err != nil {
		return nil, err
	}
	if maxBytes < 0 || maxBytes > MaxXattrListSize {
		return nil, os.ErrInvalid
	}
	if !v.sidecar {
		names, err := v.ops.list(v.file, maxBytes)
		if missingXattr(err) {
			err = errors.Join(ErrXattrNotFound, err)
		}
		return names, err
	}
	f, entries, err := v.appleDouble(ctx)
	if f != nil {
		defer func() {
			err = errors.Join(err, f.Close())
			if err != nil {
				names = nil
			}
		}()
	}
	if err != nil {
		return nil, err
	}
	names = make([]string, 0, len(entries))
	seen := map[string]bool{}
	for _, a := range entries {
		if seen[a.Name] {
			return nil, ErrXattrListMalformed
		}
		seen[a.Name] = true
		if len(a.Name)+1 > maxBytes {
			return nil, ErrXattrTooLarge
		}
		maxBytes -= len(a.Name) + 1
		names = append(names, a.Name)
	}
	return names, ctx.Err()
}

// MetadataValue is an immutable sized reader with explicit lifetime ownership.
// Close releases its backing file, if any. Reads honor the acquisition context
// and fail after Close. Metadata contents must remain unchanged while borrowed.
type MetadataValue struct {
	mu     sync.Mutex
	value  appledouble.Value
	closer io.Closer
	ctx    context.Context
	closed bool
}

func (v *MetadataValue) Size() int64 { return v.value.Size() }
func (v *MetadataValue) ReadAt(p []byte, off int64) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ctx.Err(); err != nil {
		return 0, err
	}
	if v.closed {
		return 0, os.ErrClosed
	}
	if off < 0 {
		return 0, os.ErrInvalid
	}
	return v.value.ReadAt(p, off)
}
func (v *MetadataValue) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	if v.closer != nil {
		return v.closer.Close()
	}
	return nil
}

// OpenValue returns a sized reader without allocating the resource fork's size.
// The caller must close a present value even after closing the metadata view.
// Ordinary native attributes use the existing bounded native snapshot API.
func (v *FilesystemMetadata) OpenValue(ctx context.Context, name string) (*MetadataValue, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(ctx); err != nil {
		return nil, false, err
	}
	if err := validXattrName(name); err != nil {
		return nil, false, err
	}
	if !v.sidecar {
		if name == ResourceForkName {
			_, present, err := v.ops.size(v.file, name)
			if err != nil || !present {
				return nil, false, err
			}
			if value, err := nativeFilesystemResource(ctx, v.file); err != nil || value != nil {
				return value, value != nil, err
			}
			fork, err := v.ops.fork(v.file, false)
			if err == nil {
				info, e := fork.Stat()
				if e != nil {
					return nil, false, errors.Join(e, fork.Close())
				}
				return &MetadataValue{value: io.NewSectionReader(fork, 0, info.Size()), closer: fork, ctx: ctx}, true, nil
			}
			if !errors.Is(err, errors.ErrUnsupported) && !errors.Is(err, os.ErrNotExist) {
				return nil, false, err
			}
		}
		b, present, err := v.ops.read(v.file, name, MaxXattrReadSize)
		if err != nil || !present {
			return nil, false, err
		}
		return &MetadataValue{value: bytes.NewReader(b), ctx: ctx}, true, nil
	}
	file, entries, err := v.appleDouble(ctx)
	if errors.Is(err, ErrXattrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	for _, a := range entries {
		if a.Name == name {
			return &MetadataValue{value: a.Value, closer: file, ctx: ctx}, true, nil
		}
	}
	if file != nil {
		err = file.Close()
	}
	return nil, false, err
}

// Read returns an owned bounded value. Missing and present-empty values remain
// distinct. Use OpenValue for values larger than the requested allocation bound.
func (v *FilesystemMetadata) Read(ctx context.Context, name string, maxBytes int) ([]byte, bool, error) {
	if maxBytes < 0 {
		return nil, false, os.ErrInvalid
	}
	value, present, err := v.OpenValue(ctx, name)
	if err != nil || !present {
		return nil, false, err
	}
	if value.Size() > int64(maxBytes) {
		return nil, false, errors.Join(ErrXattrTooLarge, value.Close())
	}
	b := make([]byte, int(value.Size()))
	n, err := value.ReadAt(b, 0)
	if n == len(b) && errors.Is(err, io.EOF) {
		err = nil
	}
	if n != len(b) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	err = errors.Join(err, value.Close())
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// appleDouble never follows a sidecar link. Native VFS storage is associated
// with the held object's current entry; substitution is not an empty namespace.
func (v *FilesystemMetadata) appleDouble(ctx context.Context) (*os.File, []appledouble.StreamAttr, error) {
	current, err := StatMetadata(v.parent, v.name)
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(v.identity, current) {
		return nil, nil, ErrMetadataIdentity
	}
	if current.Mode().IsRegular() && len(v.name) > 2 && strings.HasPrefix(v.name, "._") {
		// XNU rejects attributes on attribute files with EPERM. EACCES is a
		// different policy result: callers such as codesign distinguish them.
		return nil, nil, syscall.EPERM
	}
	name := "._" + v.name
	info, err := StatMetadata(v.parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !filesystemMetadataSameOwner(current, info) {
		return nil, nil, nil
	}
	f, err := v.ops.sidecar(v.parent, name)
	if err != nil {
		return nil, nil, err
	}
	fail := func(e error) (*os.File, []appledouble.StreamAttr, error) { return nil, nil, errors.Join(e, f.Close()) }
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(info, st) || !st.Mode().IsRegular() {
		return fail(ErrMetadataIdentity)
	}
	decoded, err := appledouble.DecodeFilesystemStream(ctx, io.NewSectionReader(f, 0, st.Size()), appledouble.DefaultStreamLimits())
	if errors.Is(err, appledouble.ErrNotAppleDouble) {
		return fail(ErrXattrNotFound)
	}
	if err != nil {
		return fail(err)
	}
	entries := make([]appledouble.StreamAttr, 0, len(decoded.Attrs)+2)
	if decoded.FinderInfo != [32]byte{} {
		entries = append(entries, appledouble.StreamAttr{Name: appledouble.FinderInfoName, Value: bytes.NewReader(decoded.FinderInfo[:])})
	}
	visible, err := filesystemResourceForkVisible(ctx, decoded.ResourceFork)
	if err != nil {
		return fail(err)
	}
	if visible {
		entries = append(entries, appledouble.StreamAttr{Name: ResourceForkName, Value: decoded.ResourceFork})
	}
	entries = append(entries, decoded.Attrs...)
	return f, entries, nil
}

// XNU get_xattrinfo suppresses its 286-byte placeholder by the NUL-terminated
// RF_EMPTY_TAG at byte 16, independently of the remaining resource header.
// This is filesystem visibility, not a codec transformation: retain raw bytes.
func filesystemResourceForkVisible(ctx context.Context, value appledouble.Value) (bool, error) {
	return appledouble.FilesystemForkVisible(ctx, value)
}
