package metatransport

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestObservedSourceAttribute(t *testing.T) {
	s, _, _ := fixture(t)
	r := Record{Original: "file", Materialized: "file", Kind: "file", MaterializedKind: "file"}
	value, captured, err := s.ObservedSourceAttribute(t.Context(), r, "com.apple.system.Security")
	if err != nil || captured || value != nil {
		t.Fatal(value, captured, err)
	}
	// A receiving-host empty capture cannot turn an unknown source ACL into absence.
	r.NativeCaptured = true
	value, captured, err = s.ObservedSourceAttribute(t.Context(), r, "com.apple.system.Security")
	if err != nil || captured || value != nil {
		t.Fatal(value, captured, err)
	}
	r.SourceAttributesCaptured = true
	value, captured, err = s.ObservedSourceAttribute(t.Context(), r, "com.apple.system.Security")
	if err != nil || !captured || value != nil {
		t.Fatal(value, captured, err)
	}
	raw := []byte("opaque source security")
	ref := mustBlob(t, s, raw)
	r.Darwin.Security = &ref
	value, captured, err = s.ObservedSourceAttribute(t.Context(), r, "com.apple.system.Security")
	if err != nil || !captured || value == nil {
		t.Fatal(value, captured, err)
	}
	actual := make([]byte, len(raw))
	if _, err = value.ReadAt(actual, 0); err != nil || string(actual) != string(raw) {
		t.Fatal(string(actual), err)
	}
	for _, name := range []string{"", "invalid\x00name"} {
		if _, captured, err = s.ObservedSourceAttribute(t.Context(), r, name); !errors.Is(err, ErrInvalid) || captured {
			t.Fatal(captured, err)
		}
	}
	r.Darwin.Security = &BlobRef{SHA256: "invalid", Size: 1}
	if _, captured, err = s.ObservedSourceAttribute(t.Context(), r, "security"); err == nil || captured {
		t.Fatal(captured, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, captured, err = s.ObservedSourceAttribute(ctx, Record{}, "security"); !errors.Is(err, context.Canceled) || captured {
		t.Fatal(captured, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, captured, err = s.ObservedSourceAttribute(t.Context(), Record{}, "security"); !errors.Is(err, os.ErrClosed) || captured {
		t.Fatal(captured, err)
	}
}
