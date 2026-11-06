package metatransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io/fs"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// StoreAttributeValues streams immutable borrowed values into owned blobs. Names
// remain exact byte strings. Failure returns no partial association list.
func (s *Store) StoreAttributeValues(ctx context.Context, values map[string]appledouble.Value) ([]Attribute, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	if len(values) > s.limits.Attributes {
		return nil, ErrLimit
	}
	names := make([]string, 0, len(values))
	for name, value := range values {
		if name == "" || strings.ContainsRune(name, 0) || value == nil || value.Size() < 0 {
			return nil, ErrInvalid
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Attribute, 0, len(names))
	for _, name := range names {
		value := values[name]
		ref, err := s.PutBlob(ctx, value, value.Size())
		if err != nil {
			return nil, err
		}
		out = append(out, Attribute{Name: name, Value: ref})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// BorrowAttributes verifies every blob and returns readers valid until Store.Close.
func (s *Store) BorrowAttributes(ctx context.Context, attrs []Attribute) (map[string]appledouble.Value, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	if len(attrs) > s.limits.Attributes {
		return nil, ErrLimit
	}
	out := make(map[string]appledouble.Value, len(attrs))
	for _, a := range attrs {
		if a.Name == "" || strings.ContainsRune(a.Name, 0) {
			return nil, ErrInvalid
		}
		if _, found := out[a.Name]; found {
			return nil, ErrInvalid
		}
		v, err := s.BorrowBlob(ctx, a.Value)
		if err != nil {
			return nil, err
		}
		out[a.Name] = v
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ReconcileValues applies the materialization baseline to entirely borrowed
// value maps. Unchanged host values do not leak into logical source metadata;
// changed overlaps and deletion of carried baseline values are conflicts.
// All inputs retain their owners/lifetimes. Comparison uses bounded buffers.
func ReconcileValues(ctx context.Context, native, baseline, logical map[string]appledouble.Value) (map[string]appledouble.Value, error) {
	if ctx == nil {
		return nil, fs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, values := range []map[string]appledouble.Value{native, baseline, logical} {
		for _, value := range values {
			if value == nil || value.Size() < 0 {
				return nil, ErrInvalid
			}
		}
	}
	out := make(map[string]appledouble.Value, len(logical)+len(native))
	for name, value := range logical {
		out[name] = value
	}
	for name := range baseline {
		if _, found := native[name]; !found {
			if _, carried := logical[name]; carried {
				return nil, ErrConflict
			}
		}
	}
	for name, value := range native {
		if old, found := baseline[name]; found {
			equal, err := equalValues(ctx, value, old)
			if err != nil {
				return nil, err
			}
			if equal {
				continue
			}
		}
		if original, found := logical[name]; found {
			equal, err := equalValues(ctx, value, original)
			if err != nil {
				return nil, err
			}
			if !equal {
				return nil, ErrConflict
			}
		} else {
			out[name] = value
		}
	}
	return out, ctx.Err()
}
func equalValues(ctx context.Context, a, b appledouble.Value) (bool, error) {
	if a.Size() != b.Size() {
		return false, nil
	}
	left, right := sha256.New(), sha256.New()
	if err := copyExact(ctx, left, a, a.Size()); err != nil {
		return false, err
	}
	if err := copyExact(ctx, right, b, b.Size()); err != nil {
		return false, err
	}
	return bytes.Equal(left.Sum(nil), right.Sum(nil)), nil
}
