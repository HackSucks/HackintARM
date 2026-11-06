package appledouble

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestNativeQuarantineUpdates(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/quarantine-update.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []struct {
			Name, Kind, SourceMode string
			Initial                bool
			Attrs                  []Attr
			Raw, Source            []byte
			Updates                []struct {
				RecordIndex             int
				Invalid, SourceOverride bool
				Serialized              []byte
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Records) != 288 {
		t.Fatal("missing native observations", len(fixture.Records))
	}
	for _, profile := range []QuarantineProfile{QuarantineMacOS26, QuarantineMacOS27} {
		for _, tc := range fixture.Records {
			t.Run(fmt.Sprintf("%d/%s/%t/%s/%s", profile, tc.Kind, tc.Initial, tc.SourceMode, tc.Name), func(t *testing.T) {
				f, err := Decode(tc.Raw)
				if err != nil {
					t.Fatal(err)
				}
				var source *Quarantine
				if len(tc.Source) != 0 {
					source, err = ParseQuarantineWithProfile(tc.Source, profile)
					if err != nil {
						t.Fatal(err)
					}
				}
				updates, err := f.QuarantineUpdates(profile, source)
				if err != nil || len(updates) != len(tc.Updates) {
					t.Fatalf("updates: %v %v", updates, err)
				}
				for i, want := range tc.Updates {
					got := updates[i]
					if got.RecordIndex != want.RecordIndex || got.Invalid != want.Invalid || got.SourceOverride != want.SourceOverride {
						t.Fatalf("decision %d: %+v want %+v", i, got, want)
					}
					if want.Invalid {
						if got.Quarantine != nil {
							t.Fatal("ignored record produced a value")
						}
						continue
					}
					b, err := got.Quarantine.MarshalBinaryWithProfile(profile)
					if err != nil || !bytes.Equal(b, want.Serialized) {
						t.Fatalf("value %d: %q want %q: %v", i, b, want.Serialized, err)
					}
				}
			})
		}
	}
}

func TestQuarantineUpdatesOwnershipAndPositions(t *testing.T) {
	a := []byte("q/0081;12345678;Agent;ID\x00")
	f := &File{Attrs: []Attr{{Name: "ordinary"}, {Name: QuarantineName, Value: a}, {Name: "ordinary"}, {Name: QuarantineName, Value: []byte("INVALID")}, {Name: QuarantineName, Value: a}}}
	before := append([]byte(nil), a...)
	updates, err := f.QuarantineUpdates(QuarantineMacOS27, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 3 || updates[0].RecordIndex != 1 || updates[1].RecordIndex != 3 || updates[2].RecordIndex != 4 || !updates[1].Invalid {
		t.Fatal(updates)
	}
	if !bytes.Equal(a, before) {
		t.Fatal("input mutated")
	}
	a[18] = 'Z'
	if updates[0].Quarantine.Agent != "Agent" {
		t.Fatal("value aliases record")
	}
	updates[0].Quarantine.Agent = "changed"
	if updates[2].Quarantine.Agent != "Agent" {
		t.Fatal("results alias each other")
	}
	source := &Quarantine{Timestamp: 1, Agent: "Source", Identifier: "ID"}
	original := *source
	updates, err = f.QuarantineUpdates(QuarantineMacOS26, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range updates {
		if u.Invalid || !u.SourceOverride || u.Quarantine.Flags != 1 || u.Quarantine.Agent != "Source" {
			t.Fatal(u)
		}
	}
	if *source != original {
		t.Fatal("source mutated")
	}
	updates[0].Quarantine.Agent = "changed"
	if *source != original || updates[1].Quarantine.Agent != "Source" {
		t.Fatal("source/updates alias")
	}
}

func TestQuarantineUpdatesValidation(t *testing.T) {
	for _, f := range []*File{nil, {}, {Attrs: []Attr{{Name: "ordinary"}}}} {
		for _, source := range []*Quarantine{nil, {Flags: 0x81}} {
			updates, err := f.QuarantineUpdates(QuarantineMacOS27, source)
			if err != nil || len(updates) != 0 {
				t.Fatal(updates, err)
			}
		}
		if _, err := f.QuarantineUpdates(255, nil); !errors.Is(err, ErrQuarantine) {
			t.Fatal(err)
		}
		if _, err := f.QuarantineUpdates(QuarantineMacOS27, &Quarantine{Agent: "a\x00b"}); !errors.Is(err, ErrQuarantine) {
			t.Fatal(err)
		}
	}
	f := &File{Attrs: []Attr{{Name: QuarantineName, Value: []byte("q/2000;1;;")}}}
	for _, profile := range []QuarantineProfile{QuarantineMacOS26, QuarantineMacOS27} {
		u, err := f.QuarantineUpdates(profile, nil)
		if err != nil || len(u) != 1 || u[0].Invalid != (profile == QuarantineMacOS26) {
			t.Fatal(u, err)
		}
	}
	if _, err := f.QuarantineUpdates(QuarantineMacOS26, &Quarantine{Flags: 0x2000}); !errors.Is(err, ErrQuarantine) {
		t.Fatal(err)
	}
	empty := &File{Attrs: []Attr{{Name: QuarantineName}}}
	got, err := empty.QuarantineUpdates(QuarantineMacOS27, nil)
	want := []QuarantineUpdate{{RecordIndex: 0, Invalid: true}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
}
