package recompression

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func aliasFixture(t *testing.T) (*metatransport.Store, string, metatransport.Manifest, metatransport.Record) {
	t.Helper()
	s, p, _ := fixture(t)
	r := fileRecord(t, p)
	r.LinkGroup = "inode"
	stamp := time.Unix(1234, 567).UTC()
	mode, flags := uint32(0100640), uint32(0)
	r.Darwin.Mode, r.Darwin.Flags = &mode, &flags
	r.Darwin.Birth, r.Darwin.Modify, r.Darwin.Change, r.Darwin.Access = &stamp, &stamp, &stamp, &stamp
	alias := r
	alias.Original, alias.Materialized = "alias", "alias"
	if e := os.WriteFile(filepath.Join(p, "alias"), []byte("payload"), 0600); e != nil {
		t.Fatal(e)
	}
	other := r
	other.Original, other.Materialized, other.LinkGroup = "other", "other", "other inode"
	return s, p, metatransport.Manifest{Version: 1, Records: []metatransport.Record{r, other, alias}}, r
}
func closeAliases(t *testing.T, aliases []recompressionAlias) {
	t.Helper()
	for _, a := range aliases {
		if e := a.Close(); e != nil {
			t.Fatal(e)
		}
	}
}
func TestCarrierRecompressionAliasesPublication(t *testing.T) {
	for _, edited := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "intentional edited inode"}[edited], func(t *testing.T) {
			s, _, m, r := aliasFixture(t)
			baseline := *r.Payload
			if edited {
				baseline = digest([]byte("edited payload"))
			}
			updated := r
			newMode, newFlags := uint32(0100600), uint32(32)
			now := time.Unix(4000, 0).UTC()
			updated.Darwin.Mode, updated.Darwin.Flags = &newMode, &newFlags
			updated.Darwin.Modify, updated.Darwin.Access = &now, &now
			updated.Payload = &baseline
			updated.Attributes = []metatransport.Attribute{{Name: "new", Value: digest([]byte("attribute"))}}
			updated.AppleDouble = &metatransport.BlobRef{SHA256: digest(nil).SHA256}
			other := m.Records[1]
			aliases, e := recompressionAliases(context.Background(), s, m, 0, r, baseline, updated, edited)
			if e != nil || len(aliases) != 1 {
				t.Fatal(aliases, e)
			}
			defer closeAliases(t, aliases)
			a := aliases[0]
			if a.copyPayload != edited || a.baseline != *r.Payload || !reflect.DeepEqual(a.record, mustOriginalAlias(r)) {
				t.Fatalf("retained alias state %#v", a)
			}
			got := m.Records[2]
			if got.Original != "alias" || got.Materialized != "alias" || !reflect.DeepEqual(got.Attributes, updated.Attributes) || !reflect.DeepEqual(got.AppleDouble, updated.AppleDouble) || *got.Payload != baseline || *got.Darwin.Mode != newMode || *got.Darwin.Flags != newFlags || !got.Darwin.Modify.Equal(now) || !got.Darwin.Access.Equal(now) {
				t.Fatalf("updated alias %#v", got)
			}
			if !reflect.DeepEqual(m.Records[1], other) || !reflect.DeepEqual(m.Records[0], r) {
				t.Fatal("unrelated record changed")
			}
		})
	}
	t.Run("no group", func(t *testing.T) {
		s, _, m, r := aliasFixture(t)
		r.LinkGroup = ""
		aliases, e := recompressionAliases(context.Background(), s, m, 0, r, *r.Payload, r, false)
		if e != nil || len(aliases) != 0 {
			t.Fatal(aliases, e)
		}
	})
}
func mustOriginalAlias(r metatransport.Record) metatransport.Record {
	r.Original, r.Materialized = "alias", "alias"
	return r
}
func TestCarrierRecompressionAliasesConflicts(t *testing.T) {
	cases := []struct {
		name   string
		change func(*metatransport.Record)
	}{
		{"kind", func(r *metatransport.Record) { r.Kind = "directory" }},
		{"materialization", func(r *metatransport.Record) { r.MaterializedKind = "directory" }},
		{"missing baseline", func(r *metatransport.Record) { r.Payload = nil }},
		{"different mode", func(r *metatransport.Record) { v := uint32(0100600); r.Darwin.Mode = &v }},
		{"different attribute", func(r *metatransport.Record) {
			r.Attributes = []metatransport.Attribute{{Name: "different", Value: digest(nil)}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, m, r := aliasFixture(t)
			bad := m.Records[2]
			bad.Original, bad.Materialized = "bad", "bad"
			tc.change(&bad)
			m.Records = append(m.Records, bad)
			var held *os.File
			wrapper := faultCarrier{Store: s, openPayload: func(ctx context.Context, name string) (*os.File, error) {
				f, e := s.OpenPayload(ctx, name)
				if name == "alias" {
					held = f
				}
				return f, e
			}}
			aliases, e := recompressionAliases(context.Background(), wrapper, m, 0, r, *r.Payload, r, false)
			if !errors.Is(e, metatransport.ErrConflict) || aliases != nil {
				t.Fatal(aliases, e)
			}
			if held == nil {
				t.Fatal("prior valid alias not visited")
			}
			requireFileClosed(t, held)
		})
	}
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale rejected", true: "unrecorded edit rejected"}[allow], func(t *testing.T) {
			s, p, m, r := aliasFixture(t)
			if e := os.WriteFile(filepath.Join(p, "alias"), []byte("unrecorded edit"), 0600); e != nil {
				t.Fatal(e)
			}
			aliases, e := recompressionAliases(context.Background(), s, m, 0, r, *r.Payload, r, allow)
			if !errors.Is(e, metatransport.ErrConflict) || aliases != nil {
				t.Fatal(aliases, e)
			}
		})
	}
	t.Run("baseline differs without consent", func(t *testing.T) {
		s, _, m, r := aliasFixture(t)
		aliases, e := recompressionAliases(context.Background(), s, m, 0, r, digest([]byte("new primary")), r, false)
		if !errors.Is(e, metatransport.ErrConflict) || aliases != nil {
			t.Fatal(aliases, e)
		}
	})
	t.Run("missing alias", func(t *testing.T) {
		s, p, m, r := aliasFixture(t)
		if e := os.Remove(filepath.Join(p, "alias")); e != nil {
			t.Fatal(e)
		}
		aliases, e := recompressionAliases(context.Background(), s, m, 0, r, *r.Payload, r, false)
		if !errors.Is(e, os.ErrNotExist) || aliases != nil {
			t.Fatal(aliases, e)
		}
	})
	t.Run("cancelled hash closes alias", func(t *testing.T) {
		s, _, m, r := aliasFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var held *os.File
		wrapper := faultCarrier{Store: s, openPayload: func(ctx context.Context, name string) (*os.File, error) {
			f, e := s.OpenPayload(ctx, name)
			held = f
			cancel()
			return f, e
		}}
		aliases, e := recompressionAliases(ctx, wrapper, m, 0, r, *r.Payload, r, false)
		if !errors.Is(e, context.Canceled) || aliases != nil {
			t.Fatal(aliases, e)
		}
		if held == nil {
			t.Fatal("missing held alias")
		}
		requireFileClosed(t, held)
	})
}
func TestCarrierRecompressionAliasState(t *testing.T) {
	_, _, _, r := aliasFixture(t)
	r.Attributes = []metatransport.Attribute{{Name: "z", Value: digest([]byte("z"))}, {Name: "a", Value: digest(nil)}}
	r.NativeAttributes = []metatransport.Attribute{{Name: "host", Value: digest(nil)}}
	r.NativeCaptured, r.NativeUnsupported = true, true
	alias := r
	alias.Original, alias.Materialized = "different", "different"
	alias.NativeAttributes = nil
	alias.NativeCaptured, alias.NativeUnsupported = false, false
	zone := time.FixedZone("foreign", 3600)
	for _, value := range []**time.Time{&alias.Darwin.Birth, &alias.Darwin.Modify, &alias.Darwin.Change, &alias.Darwin.Access} {
		v := (*value).In(zone)
		*value = &v
	}
	alias.Attributes = []metatransport.Attribute{r.Attributes[1], r.Attributes[0]}
	first, second := recompressionAliasState(r), recompressionAliasState(alias)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("equivalent logical aliases differ: %#v %#v", first, second)
	}
	if r.Attributes[0].Name != "z" || alias.Darwin.Modify.Location() != zone || r.NativeAttributes == nil || r.Original == "" {
		t.Fatal("normalization changed caller storage")
	}
	first.Attributes[0].Name = "mutated"
	if r.Attributes[1].Name != "a" {
		t.Fatal("attribute slice borrowed")
	}
	*first.Darwin.Modify = time.Time{}
	if r.Darwin.Modify.IsZero() {
		t.Fatal("timestamp pointer borrowed")
	}
	if got := recompressionAliasState(metatransport.Record{}); !reflect.DeepEqual(got, metatransport.Record{}) {
		t.Fatal(got)
	}
}
func TestCarrierRecompressionPayloadAssociation(t *testing.T) {
	s, p, _, r := aliasFixture(t)
	file, e := os.Open(filepath.Join(p, r.Materialized))
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	if e = s.CheckPayload(t.Context(), r.Materialized, file); e != nil {
		t.Fatal(e)
	}
	if e = s.CheckPayload(t.Context(), "missing/file", file); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	if e = s.CheckPayload(t.Context(), "file/child", file); !errors.Is(e, metatransport.ErrInvalid) {
		t.Fatal(e)
	}
	if e = s.CheckPayload(t.Context(), "missing", file); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	if e = s.CheckPayload(t.Context(), "alias", file); !errors.Is(e, metatransport.ErrConflict) {
		t.Fatal("different inode accepted", e)
	}
	if e = os.Mkdir(filepath.Join(p, "directory"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = s.CheckPayload(t.Context(), "directory", file); !errors.Is(e, metatransport.ErrConflict) {
		t.Fatal("directory accepted", e)
	}
	if e = file.Close(); e != nil {
		t.Fatal(e)
	}
	statCause := closedFileStatCause(t, file)
	if e = s.CheckPayload(t.Context(), r.Materialized, file); !errors.Is(e, statCause) {
		t.Fatal(e)
	}
}

func TestCarrierRecompressionPayloadStatError(t *testing.T) {
	s, _, _, r := aliasFixture(t)
	sentinel := errors.New("held payload stat failure")
	if err := s.CheckPayload(t.Context(), r.Materialized, failingPayloadStat{sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("lost held Stat error: %v", err)
	}
}
