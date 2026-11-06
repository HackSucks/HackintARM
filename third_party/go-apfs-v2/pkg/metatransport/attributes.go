package metatransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// Attribute names are byte strings. Base64 JSON avoids silently replacing
// non-UTF-8 names returned by native Linux/Windows namespaces.
func (a Attribute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name  []byte  `json:"nameBytes"`
		Value BlobRef `json:"value"`
	}{[]byte(a.Name), a.Value})
}
func (a *Attribute) UnmarshalJSON(b []byte) error {
	if err := uniqueJSON(b); err != nil {
		return err
	}
	var wire struct {
		Name  []byte  `json:"nameBytes"`
		Value BlobRef `json:"value"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&wire); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return ErrInvalid
	}
	a.Name = string(wire.Name)
	a.Value = wire.Value
	return nil
}

// StoreAttributes captures owned carrier blobs in deterministic logical-name
// order. Input bytes are borrowed and must not change until return. Cancellation
// or failure returns no partial attribute list; unreferenced blobs are harmless.
func (s *Store) StoreAttributes(ctx context.Context, values map[string][]byte) ([]Attribute, error) {
	borrowed := make(map[string]appledouble.Value, len(values))
	for name, value := range values {
		borrowed[name] = bytes.NewReader(value)
	}
	return s.StoreAttributeValues(ctx, borrowed)
}

// ReadAttributes materializes a bounded logical snapshot. maxBytes is the total
// resident value budget; larger values remain accessible using OpenBlob. Empty
// attributes are non-nil empty values. No partial snapshot escapes on failure.
func (s *Store) ReadAttributes(ctx context.Context, attrs []Attribute, maxBytes int64) (map[string][]byte, error) {
	if e := s.check(ctx); e != nil {
		return nil, e
	}
	if maxBytes < 0 {
		return nil, ErrLimit
	}
	if len(attrs) > s.limits.Attributes {
		return nil, ErrLimit
	}
	values := make(map[string][]byte, len(attrs))
	remaining := maxBytes
	for _, a := range attrs {
		if a.Name == "" || strings.ContainsRune(a.Name, 0) {
			return nil, ErrInvalid
		}
		if _, ok := values[a.Name]; ok {
			return nil, ErrInvalid
		}
		if !validRef(a.Value) {
			return nil, ErrInvalid
		}
		if a.Value.Size > remaining || a.Value.Size > int64(int(^uint(0)>>1)) {
			return nil, ErrLimit
		}
		f, e := s.OpenBlob(ctx, a.Value)
		if e != nil {
			return nil, e
		}
		b := make([]byte, int(a.Value.Size))
		_, e = io.ReadFull(f, b)
		e = errors.Join(e, f.Close())
		if e != nil {
			return nil, e
		}
		remaining -= a.Value.Size
		values[a.Name] = b
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	return values, nil
}

// MergeAttributes coalesces identical native/carrier values and preserves names
// present in only one namespace. Conflicting bytes are an error, never an
// implicit winner. Inputs must be complete captures; nil means known empty.
// The returned snapshot owns its bytes and distinguishes empty from absent.
func MergeAttributes(native, carrier map[string][]byte) (map[string][]byte, error) {
	out := make(map[string][]byte, len(native)+len(carrier))
	for name, value := range native {
		out[name] = bytes.Clone(value)
		if out[name] == nil {
			out[name] = []byte{}
		}
	}
	for name, value := range carrier {
		if current, ok := out[name]; ok && !bytes.Equal(current, value) {
			return nil, fmt.Errorf("attribute %q: %w", name, ErrConflict)
		}
		out[name] = bytes.Clone(value)
		if out[name] == nil {
			out[name] = []byte{}
		}
	}
	return out, nil
}

// ReadRecordAttributes restores raw attributes and validates the optional
// canonical AppleDouble copy against them. A separately hashed but inconsistent
// sidecar cannot silently override logical state. The security record is merged
// with the same conflict rule as any other duplicate representation.
func (s *Store) ReadRecordAttributes(ctx context.Context, r Record, maxBytes int64) (map[string][]byte, error) {
	values, e := s.ReadAttributes(ctx, r.Attributes, maxBytes)
	if e != nil {
		return nil, e
	}
	if r.AppleDouble != nil {
		streamValues := make(map[string]appledouble.Value, len(values))
		for name, value := range values {
			streamValues[name] = bytes.NewReader(value)
		}
		if e = s.validateValueSidecar(ctx, r.AppleDouble, streamValues); e != nil {
			return nil, e
		}
	}
	if r.Darwin.Security != nil {
		if existing, present := values["com.apple.system.Security"]; present {
			sum := sha256.Sum256(existing)
			if *r.Darwin.Security != (BlobRef{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(existing))}) {
				return nil, ErrConflict
			}
			return values, nil
		}
		remaining := maxBytes
		for _, value := range values {
			remaining -= int64(len(value))
		}
		security, e := s.ReadAttributes(ctx, []Attribute{{Name: "com.apple.system.Security", Value: *r.Darwin.Security}}, remaining)
		if e != nil {
			return nil, e
		}
		return MergeAttributes(values, security)
	}
	return values, nil
}

// ReconcileAttributes excludes unchanged materialization metadata using a
// captured host baseline. New or changed host values are explicit user changes;
// they must agree with overlapping logical metadata. A host deletion of a name
// also carried logically is a conflict, not permission to silently resurrect it.
// No attribute name (including provenance) receives a special exemption.
func ReconcileAttributes(native, baseline, logical map[string][]byte) (map[string][]byte, error) {
	delta := make(map[string][]byte)
	for name, value := range native {
		old, present := baseline[name]
		if !present || !bytes.Equal(old, value) {
			delta[name] = value
		}
	}
	for name := range baseline {
		if _, present := native[name]; !present {
			if _, carried := logical[name]; carried {
				return nil, fmt.Errorf("deleted attribute %q: %w", name, ErrConflict)
			}
		}
	}
	return MergeAttributes(delta, logical)
}

// ReadNativeBaseline reads a complete recorded materialization namespace.
// Uncaptured state is invalid; confirmed unsupported means a known empty native
// namespace and is distinct from a failed capture.
func (s *Store) ReadNativeBaseline(ctx context.Context, r Record, maxBytes int64) (map[string][]byte, error) {
	if e := s.check(ctx); e != nil {
		return nil, e
	}
	if r.NativeCaptured == r.NativeUnsupported || (!r.NativeCaptured && len(r.NativeAttributes) > 0) {
		return nil, ErrInvalid
	}
	if r.NativeUnsupported {
		return map[string][]byte{}, nil
	}
	return s.ReadAttributes(ctx, r.NativeAttributes, maxBytes)
}

func (s *Store) check(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready(ctx)
}
