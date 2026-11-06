// Package metatransport preserves logical metadata in an explicitly selected
// directory, independently of the payload filesystem's native capabilities.
package metatransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid metadata carrier")
	ErrConflict = errors.New("metadata carrier changed")
	ErrLimit    = errors.New("metadata carrier resource limit")
	ErrCorrupt  = errors.New("metadata carrier content mismatch")
)

// Limits are explicit allocation and storage budgets. Zero permits no bytes or
// records; callers wanting defaults must use DefaultLimits.
type Limits struct {
	ManifestBytes, BlobBytes int64
	Records, Attributes      int
}

func DefaultLimits() Limits { return Limits{16 << 20, 1 << 40, 100000, 1000000} }

// BlobRef addresses an immutable value by its complete SHA-256 and byte length.
type BlobRef struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Attribute preserves a logical name independently of native EA namespaces.
type Attribute struct {
	Name  string  `json:"name"`
	Value BlobRef `json:"value"`
}

// DarwinState is logical source metadata, not a claim of host enforcement.
// Nil optional fields mean uncaptured; explicit zero fields remain real values.
type DarwinState struct {
	UID               *uint32    `json:"uid,omitempty"`
	GID               *uint32    `json:"gid,omitempty"`
	Mode              *uint32    `json:"mode,omitempty"`
	Flags             *uint32    `json:"flags,omitempty"`
	Birth             *time.Time `json:"birth,omitempty"`
	Modify            *time.Time `json:"modify,omitempty"`
	Change            *time.Time `json:"change,omitempty"`
	Access            *time.Time `json:"access,omitempty"`
	Security          *BlobRef   `json:"security,omitempty"`
	Identity          *BlobRef   `json:"identity,omitempty"`
	QuarantineContext *BlobRef   `json:"quarantineContext,omitempty"`
}

// Record binds metadata to one original name and its materialized payload name.
// Payload is a baseline content digest for regular files, including degraded
// links. Target contains the original link target; LinkGroup retains aliases.
// Root directories use ".". A link represented as a regular file has Kind
// "symlink" and MaterializedKind "file".
type Record struct {
	// SourceAttributesCaptured records a complete successful source attribute
	// enumeration, independently of receiving-host NativeCaptured. Older manifests
	// omit this field and remain uncaptured. Older strict readers cannot read
	// manifests containing this field and require an updated reader.
	SourceAttributesCaptured bool        `json:"sourceAttributesCaptured,omitempty"`
	Original                 string      `json:"original"`
	Materialized             string      `json:"materialized"`
	Kind                     string      `json:"kind"`
	MaterializedKind         string      `json:"materializedKind"`
	Target                   string      `json:"target,omitempty"`
	LinkGroup                string      `json:"linkGroup,omitempty"`
	Payload                  *BlobRef    `json:"payload,omitempty"`
	AppleDouble              *BlobRef    `json:"appleDouble,omitempty"`
	Attributes               []Attribute `json:"attributes,omitempty"`
	NativeAttributes         []Attribute `json:"nativeAttributes,omitempty"`
	NativeCaptured           bool        `json:"nativeCaptured,omitempty"`
	NativeUnsupported        bool        `json:"nativeUnsupported,omitempty"`
	Darwin                   DarwinState `json:"darwin"`
}

// Manifest is versioned independently of AppleDouble. Generation is advanced
// only by Commit; the supplied generation must equal the expected baseline.
type Manifest struct {
	Version    uint32   `json:"version"`
	Generation uint64   `json:"generation"`
	Records    []Record `json:"records"`
}

// Store holds both directory identities open. Methods serialize local writes;
// an exclusive lock file and generation check reject competing writers. External
// mutation of payload objects or carrier storage during an operation is excluded.
// Roots may be renamed while open. Callers retain the directories after Close.
type Store struct {
	payload, metadata carrierRoot
	limits            Limits
	writeMu           sync.Mutex
	mu                sync.Mutex
	closed            bool
}

// Open opens existing, separately selected directories. It never discovers a
// carrier by a payload filename. Equal, aliased or nested roots are rejected.
type carrierRoot interface {
	Lstat(string) (os.FileInfo, error)
	Stat(string) (os.FileInfo, error)
	Open(string) (*os.File, error)
	OpenFile(string, int, os.FileMode) (*os.File, error)
	Readlink(string) (string, error)
	Rename(string, string) error
	Remove(string) error
	Close() error
}

func Open(payloadDir, metadataDir string, limits Limits) (*Store, error) {
	if limits.ManifestBytes < 0 || limits.ManifestBytes == int64(^uint64(0)>>1) || limits.BlobBytes < 0 || limits.Records < 0 || limits.Attributes < 0 {
		return nil, ErrLimit
	}
	paths := [2]string{payloadDir, metadataDir}
	for i, p := range paths {
		a, e := filepath.Abs(p)
		if e != nil {
			return nil, e
		}
		a, e = filepath.EvalSymlinks(a)
		if e != nil {
			return nil, e
		}
		paths[i] = a
	}
	for i := range paths {
		rel, e := filepath.Rel(paths[i], paths[1-i])
		if e != nil {
			if filepath.VolumeName(paths[i]) != filepath.VolumeName(paths[1-i]) {
				continue
			}
			return nil, e
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return nil, fmt.Errorf("overlapping roots: %w", ErrInvalid)
		}
	}
	p, e := os.OpenRoot(paths[0])
	if e != nil {
		return nil, e
	}
	m, e := os.OpenRoot(paths[1])
	if e != nil {
		return nil, errors.Join(e, p.Close())
	}
	pi, e := p.Stat(".")
	if e != nil {
		return nil, errors.Join(e, p.Close(), m.Close())
	}
	mi, e := m.Stat(".")
	if e != nil {
		return nil, errors.Join(e, p.Close(), m.Close())
	}
	if os.SameFile(pi, mi) {
		return nil, errors.Join(ErrInvalid, p.Close(), m.Close())
	}
	return &Store{payload: p, metadata: m, limits: limits}, nil
}
func (s *Store) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.payload.Close(), s.metadata.Close())
}
func (s *Store) ready(ctx context.Context) error {
	if ctx == nil {
		return fs.ErrInvalid
	}
	if s.closed {
		return os.ErrClosed
	}
	return ctx.Err()
}
func validRef(r BlobRef) bool {
	b, e := hex.DecodeString(r.SHA256)
	return e == nil && len(b) == sha256.Size && r.SHA256 == strings.ToLower(r.SHA256) && r.Size >= 0
}
func validPath(p string) bool {
	return fs.ValidPath(p) && !strings.ContainsRune(p, 0) && (filepath.Separator != 92 || !strings.ContainsRune(p, 92)) && filepath.IsLocal(filepath.FromSlash(p))
}
func blobName(r BlobRef) string { return "blob-" + r.SHA256 }

// checkParents rejects redirected intermediate directories as well as escapes.
func checkParents(root carrierRoot, name string) error {
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		info, e := root.Lstat(strings.Join(parts[:i], "/"))
		if e != nil {
			return e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
	}
	return nil
}

// openRegular excludes symlink/reparse redirection and checks that the opened
// object is the one inspected. Root containment remains enforced by os.Root.
func openRegular(root carrierRoot, name string) (*os.File, error) {
	if e := checkParents(root, name); e != nil {
		return nil, e
	}
	before, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() {
		return nil, ErrInvalid
	}
	f, e := root.Open(name)
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil {
		return nil, errors.Join(e, f.Close())
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.Join(ErrConflict, f.Close())
	}
	return f, nil
}
func copyExact(ctx context.Context, dst io.Writer, src io.ReaderAt, size int64) error {
	if ctx == nil || src == nil || size < 0 {
		return ErrInvalid
	}
	buf := make([]byte, 64<<10)
	for off := int64(0); off < size; {
		if e := ctx.Err(); e != nil {
			return e
		}
		n := int64(len(buf))
		if size-off < n {
			n = size - off
		}
		got, e := src.ReadAt(buf[:n], off)
		if got != int(n) {
			return errors.Join(io.ErrUnexpectedEOF, e)
		}
		if e != nil && e != io.EOF {
			return e
		}
		w, e := dst.Write(buf[:got])
		if e != nil {
			return e
		}
		if w != got {
			return io.ErrShortWrite
		}
		off += n
	}
	return ctx.Err()
}
func verify(ctx context.Context, f interface {
	io.ReaderAt
	Stat() (os.FileInfo, error)
}, ref BlobRef) error {
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if info.Size() != ref.Size {
		return ErrCorrupt
	}
	h := sha256.New()
	if e = copyExact(ctx, h, f, ref.Size); e != nil {
		return e
	}
	if hex.EncodeToString(h.Sum(nil)) != ref.SHA256 {
		return ErrCorrupt
	}
	return nil
}

// PutBlob writes with bounded scratch, syncs and publishes an immutable blob.
// It does not publish a manifest. An unreferenced blob after failure is harmless.
// src is borrowed and must remain immutable and open until this call returns.
// Reads may use this Store's borrowed values, including through range wrappers.
// The writer/close lock pins directory lifetime without holding the read-state
// mutex while invoking caller-provided ReaderAt methods.
func (s *Store) PutBlob(ctx context.Context, src io.ReaderAt, size int64) (ref BlobRef, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if e := s.ready(ctx); e != nil {
		return ref, e
	}
	if size < 0 || size > s.limits.BlobBytes {
		return ref, ErrLimit
	}
	tmp := ".blob-" + rand.Text()
	f, e := s.metadata.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ref, e
	}
	defer func() { err = errors.Join(err, f.Close(), removeAbsentOK(s.metadata, tmp)) }()
	h := sha256.New()
	if e = copyExact(ctx, io.MultiWriter(f, h), src, size); e != nil {
		return ref, e
	}
	if e = f.Sync(); e != nil {
		return ref, e
	}
	ref = BlobRef{hex.EncodeToString(h.Sum(nil)), size}
	release, e := s.acquire()
	if e != nil {
		return ref, e
	}
	defer func() { err = errors.Join(err, release()) }()
	old, e := openRegular(s.metadata, blobName(ref))
	if e == nil {
		e = verify(ctx, old, ref)
		e = errors.Join(e, old.Close())
		return ref, e
	}
	if !errors.Is(e, fs.ErrNotExist) {
		return ref, e
	}
	// A shared writer lock protects publication without requiring hard links,
	// which FAT/exFAT cannot supply. Uncoordinated storage mutation is excluded.
	if e = s.metadata.Rename(tmp, blobName(ref)); e != nil {
		return ref, e
	}
	return ref, nil
}
func removeAbsentOK(root carrierRoot, name string) error {
	e := root.Remove(name)
	if errors.Is(e, fs.ErrNotExist) {
		return nil
	}
	return e
}

// OpenBlob verifies the whole digest before returning the held file. The caller
// owns the returned file and must close it. Its position remains at byte zero.
func (s *Store) OpenBlob(ctx context.Context, ref BlobRef) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(ctx); e != nil {
		return nil, e
	}
	return s.openBlob(ctx, ref)
}
func (s *Store) openBlob(ctx context.Context, ref BlobRef) (*os.File, error) {
	if !validRef(ref) {
		return nil, ErrInvalid
	}
	if ref.Size > s.limits.BlobBytes {
		return nil, ErrLimit
	}
	f, e := openRegular(s.metadata, blobName(ref))
	if e != nil {
		return nil, e
	}
	if e = verify(ctx, f, ref); e != nil {
		return nil, errors.Join(e, f.Close())
	}
	return f, nil
}
func recordRefs(r Record) []BlobRef {
	var out []BlobRef
	for _, a := range r.Attributes {
		out = append(out, a.Value)
	}
	for _, a := range r.NativeAttributes {
		out = append(out, a.Value)
	}
	for _, p := range []*BlobRef{r.AppleDouble, r.Darwin.Security, r.Darwin.Identity, r.Darwin.QuarantineContext} {
		if p != nil {
			out = append(out, *p)
		}
	}
	return out
}
func (s *Store) validate(m Manifest) error {
	if m.Version != 1 {
		return ErrInvalid
	}
	if len(m.Records) > s.limits.Records {
		return ErrLimit
	}
	names := map[string]bool{}
	paths := map[string]bool{}
	count := 0
	for _, r := range m.Records {
		if !fs.ValidPath(r.Original) || strings.ContainsRune(r.Original, 0) || !validPath(r.Materialized) || names[r.Original] || paths[r.Materialized] {
			return ErrInvalid
		}
		names[r.Original] = true
		paths[r.Materialized] = true
		if r.Kind != "file" && r.Kind != "directory" && r.Kind != "symlink" {
			return ErrInvalid
		}
		if r.MaterializedKind != "file" && r.MaterializedKind != "directory" && r.MaterializedKind != "symlink" {
			return ErrInvalid
		}
		if r.Kind != r.MaterializedKind && !(r.Kind == "symlink" && r.MaterializedKind == "file") {
			return ErrInvalid
		}
		if (r.Kind == "symlink") != (r.Target != "") || strings.ContainsRune(r.Target, 0) || (r.LinkGroup != "" && r.Kind != "file") {
			return ErrInvalid
		}
		if (r.MaterializedKind == "file") != (r.Payload != nil) {
			return ErrInvalid
		}
		if r.Payload != nil && !validRef(*r.Payload) {
			return ErrInvalid
		}
		if (r.Original == "." || r.Materialized == ".") && (r.Kind != "directory" || r.Original != r.Materialized) {
			return ErrInvalid
		}
		if (r.NativeCaptured && r.NativeUnsupported) || (!r.NativeCaptured && len(r.NativeAttributes) > 0) {
			return ErrInvalid
		}
		for _, namespace := range [][]Attribute{r.Attributes, r.NativeAttributes} {
			attrNames := map[string]bool{}
			for _, a := range namespace {
				if a.Name == "" || strings.ContainsRune(a.Name, 0) || attrNames[a.Name] {
					return ErrInvalid
				}
				attrNames[a.Name] = true
				count++
				if count > s.limits.Attributes {
					return ErrLimit
				}
			}
		}
		for _, ref := range recordRefs(r) {
			if !validRef(ref) {
				return ErrInvalid
			}
			if ref.Size > s.limits.BlobBytes {
				return ErrLimit
			}
		}
	}
	return nil
}

// Load returns an owned, strictly decoded manifest. A missing manifest means an
// uninitialized carrier (fs.ErrNotExist), never an empty metadata set. Referenced
// blobs are verified; payload content may have intentionally changed and is
// checked separately with VerifyPayload.
func (s *Store) Load(ctx context.Context) (Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(ctx); e != nil {
		return Manifest{}, e
	}
	return s.load(ctx)
}
func (s *Store) load(ctx context.Context) (Manifest, error) {
	var m Manifest
	f, e := openRegular(s.metadata, "manifest.json")
	if e != nil {
		return m, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return m, e
	}
	if info.Size() > s.limits.ManifestBytes {
		return m, ErrLimit
	}
	b, e := io.ReadAll(io.LimitReader(f, s.limits.ManifestBytes+1))
	if e != nil {
		return m, e
	}
	if int64(len(b)) > s.limits.ManifestBytes {
		return m, ErrLimit
	}
	if e = uniqueJSON(b); e != nil {
		return m, e
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&m); e != nil {
		return m, errors.Join(ErrInvalid, e)
	}
	if m.Generation == 0 {
		return m, ErrInvalid
	}
	if e = s.validate(m); e != nil {
		return m, e
	}
	if e = s.verifyRefs(ctx, m); e != nil {
		return m, e
	}
	return m, nil
}
func uniqueJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return ErrLimit
		}
		t, e := d.Token()
		if e != nil {
			return errors.Join(ErrInvalid, e)
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, e = d.Token()
				if e != nil {
					return ErrInvalid
				}
				k, ok := t.(string)
				if !ok || seen[k] {
					return ErrInvalid
				}
				seen[k] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		default:
			return ErrInvalid
		}
		_, e = d.Token()
		return e
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	return nil
}
func (s *Store) verifyRefs(ctx context.Context, m Manifest) error {
	seen := map[BlobRef]bool{}
	for _, r := range m.Records {
		for _, ref := range recordRefs(r) {
			if seen[ref] {
				continue
			}
			seen[ref] = true
			f, e := s.openBlob(ctx, ref)
			if e != nil {
				return errors.Join(ErrCorrupt, e)
			}
			if e = f.Close(); e != nil {
				return e
			}
		}
	}
	return ctx.Err()
}

func (s *Store) acquire() (func() error, error) {
	lock, e := s.metadata.OpenFile(".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(e, fs.ErrExist) {
		return nil, ErrConflict
	}
	if e != nil {
		return nil, e
	}
	return func() error { return errors.Join(lock.Close(), s.metadata.Remove(".lock")) }, nil
}

// Commit publishes generation expected+1 after verifying every referenced blob.
// It rejects concurrent writers and stale generations. Payload changes are not
// rolled back. The caller must validate payload baselines before selecting them.
func (s *Store) Commit(ctx context.Context, m Manifest, expected uint64) error {
	_, err := s.commitWithPayload(ctx, m, expected, nil)
	return err
}

// commitWithPayload prepares durable manifest bytes and verifies the generation
// under the writer lock before an optional payload transition. A failed final
// rename can leave the payload changed; existing baseline verification makes
// that state explicit instead of reusing obsolete compression storage.
func (s *Store) commitWithPayload(ctx context.Context, m Manifest, expected uint64, transition func() error) (published bool, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	if e := s.ready(ctx); e != nil {
		return false, e
	}
	if m.Generation != expected || expected == ^uint64(0) {
		return false, ErrConflict
	}
	if e := s.validate(m); e != nil {
		return false, e
	}
	release, e := s.acquire()
	if e != nil {
		return false, e
	}
	defer func() { err = errors.Join(err, release()) }()
	_, existsErr := s.metadata.Lstat("manifest.json")
	current, e := s.load(ctx)
	if errors.Is(existsErr, fs.ErrNotExist) {
		if expected != 0 {
			return false, ErrConflict
		}
	} else if e != nil {
		return false, e
	} else if current.Generation != expected {
		return false, ErrConflict
	}
	if e = s.verifyRefs(ctx, m); e != nil {
		return false, e
	}
	m.Generation = expected + 1
	b, e := json.Marshal(m)
	if e != nil {
		return false, e
	}
	if int64(len(b)) > s.limits.ManifestBytes {
		return false, ErrLimit
	}
	tmp := ".manifest-" + rand.Text()
	f, e := s.metadata.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return false, e
	}
	defer func() { err = errors.Join(err, removeAbsentOK(s.metadata, tmp)) }()
	_, writeErr := f.Write(b)
	e = errors.Join(writeErr, f.Sync(), f.Close())
	if e != nil {
		return false, e
	}
	if e = ctx.Err(); e != nil {
		return false, e
	}
	// The writer lock pins root lifetime. Release the read-state mutex before
	// caller I/O so borrowed values and association checks cannot deadlock.
	s.mu.Unlock()
	locked = false
	if transition != nil {
		if e = transition(); e != nil {
			return false, e
		}
	}
	err = s.metadata.Rename(tmp, "manifest.json")
	return err == nil, err
}

// VerifyPayload checks an association baseline without following a symlink.
// Changed content is a conflict; callers explicitly decide whether to preserve
// its metadata, recapture it, or reject it. No carrier/native winner is implied.
func (s *Store) VerifyPayload(ctx context.Context, r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(ctx); e != nil {
		return e
	}
	if e := s.validate(Manifest{Version: 1, Records: []Record{r}}); e != nil {
		return e
	}
	if e := checkParents(s.payload, r.Materialized); e != nil {
		return e
	}
	info, e := s.payload.Lstat(r.Materialized)
	if e != nil {
		return e
	}
	switch r.MaterializedKind {
	case "directory":
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrConflict
		}
	case "symlink":
		if info.Mode()&os.ModeSymlink == 0 {
			return ErrConflict
		}
		target, e := s.payload.Readlink(r.Materialized)
		if e != nil {
			return e
		}
		if target != r.Target {
			return ErrConflict
		}
	case "file":
		f, e := openRegular(s.payload, r.Materialized)
		if e != nil {
			return e
		}
		e = verify(ctx, f, *r.Payload)
		e = errors.Join(e, f.Close())
		if e != nil {
			return errors.Join(ErrConflict, e)
		}
	}
	return ctx.Err()
}
