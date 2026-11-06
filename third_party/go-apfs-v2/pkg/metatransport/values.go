package metatransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// borrowedValue retains a root and object identity, not one descriptor per
// value. Each ReadAt pins a checked descriptor for that read and closes it.
// This bounds descriptor use for trees containing thousands of attributes.
type borrowedValue struct {
	store *Store
	root  carrierRoot
	name  string
	info  os.FileInfo
	ctx   context.Context
}

func (v *borrowedValue) Size() int64 { return v.info.Size() }
func (v *borrowedValue) ReadAt(p []byte, off int64) (n int, err error) {
	v.store.mu.Lock()
	defer v.store.mu.Unlock()
	if err = v.store.ready(v.ctx); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	f, err := openRegular(v.root, v.name)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !os.SameFile(info, v.info) || info.Size() != v.info.Size() {
		return 0, ErrConflict
	}
	return io.NewSectionReader(f, 0, v.Size()).ReadAt(p, off)
}

// BorrowBlob verifies content and returns a bounded-memory reader valid until
// Store.Close. Every read checks object identity and size through the held root.
// The caller must exclude external mutation, including same-size content edits.
// Unlike OpenBlob, it does not consume a descriptor for the reader's lifetime.
func (s *Store) BorrowBlob(ctx context.Context, ref BlobRef) (appledouble.Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	f, err := s.openBlob(ctx, ref)
	if err != nil {
		return nil, err
	}
	info, statErr := f.Stat()
	err = errors.Join(statErr, f.Close())
	if err != nil {
		return nil, err
	}
	return &borrowedValue{s, s.metadata, blobName(ref), info, ctx}, nil
}

// BorrowPayload borrows a regular payload file's current contents. It permits
// intentional data edits. Use VerifyPayload first when unchanged content is a
// prerequisite, for example when selecting an original compressed fork.
func (s *Store) BorrowPayload(ctx context.Context, name string) (appledouble.Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if !validPath(name) {
		return nil, ErrInvalid
	}
	f, err := openRegular(s.payload, name)
	if err != nil {
		return nil, err
	}
	info, statErr := f.Stat()
	err = errors.Join(statErr, f.Close())
	if err != nil {
		return nil, err
	}
	return &borrowedValue{s, s.payload, name, info, ctx}, nil
}

// BorrowRecordAttributes validates all representations and returns borrowed
// values without materializing large forks or ordinary attributes. Raw values
// beyond AppleDouble's wire limits remain valid when no sidecar is supplied.
func (s *Store) BorrowRecordAttributes(ctx context.Context, r Record) (map[string]appledouble.Value, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	if len(r.Attributes) > s.limits.Attributes {
		return nil, ErrLimit
	}
	values := make(map[string]appledouble.Value, len(r.Attributes))
	refs := make(map[string]BlobRef, len(r.Attributes))
	for _, a := range r.Attributes {
		if a.Name == "" || strings.ContainsRune(a.Name, 0) {
			return nil, ErrInvalid
		}
		if _, duplicate := values[a.Name]; duplicate {
			return nil, ErrInvalid
		}
		value, err := s.BorrowBlob(ctx, a.Value)
		if err != nil {
			return nil, err
		}
		values[a.Name] = value
		refs[a.Name] = a.Value
	}
	if err := s.validateValueSidecar(ctx, r.AppleDouble, values); err != nil {
		return nil, err
	}
	if r.Darwin.Security != nil {
		const security = "com.apple.system.Security"
		if old, exists := refs[security]; exists {
			if old != *r.Darwin.Security {
				return nil, ErrConflict
			}
		} else {
			value, err := s.BorrowBlob(ctx, *r.Darwin.Security)
			if err != nil {
				return nil, err
			}
			values[security] = value
		}
	}
	return values, ctx.Err()
}

func (s *Store) validateValueSidecar(ctx context.Context, ref *BlobRef, values map[string]appledouble.Value) error {
	if ref == nil {
		return nil
	}
	stream := appledouble.StreamFile{}
	for name, value := range values {
		switch name {
		case appledouble.FinderInfoName:
			if value.Size() != 32 {
				return ErrConflict
			}
			n, err := value.ReadAt(stream.FinderInfo[:], 0)
			if n != 32 {
				return errors.Join(io.ErrUnexpectedEOF, err)
			}
			if err != nil && err != io.EOF {
				return err
			}
		case appledouble.ResourceForkName:
			stream.ResourceFork = value
		default:
			stream.Attrs = append(stream.Attrs, appledouble.StreamAttr{Name: name, Value: value})
		}
	}
	h := sha256.New()
	size, err := stream.EncodeTo(ctx, h, appledouble.DefaultStreamLimits())
	if err != nil {
		return err
	}
	if *ref != (BlobRef{SHA256: hex.EncodeToString(h.Sum(nil)), Size: size}) {
		return ErrConflict
	}
	_, err = s.BorrowBlob(ctx, *ref)
	return err
}

// ReconcileAttributeValues excludes unchanged materialization metadata and
// merges native changes only when they agree with overlapping logical values.
// Baseline nil selects ordinary strict merging. Returned native values own
// their bytes; logical readers retain the source's borrowed lifetime.
func ReconcileAttributeValues(ctx context.Context, native, baseline map[string][]byte, logical map[string]appledouble.Value) (map[string]appledouble.Value, error) {
	owned := make(map[string]appledouble.Value, len(native))
	prior := make(map[string]appledouble.Value, len(baseline))
	for name, value := range native {
		owned[name] = bytes.NewReader(bytes.Clone(value))
	}
	for name, value := range baseline {
		prior[name] = bytes.NewReader(value)
	}
	return ReconcileValues(ctx, owned, prior, logical)
}
