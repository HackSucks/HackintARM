package recompression

import (
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func TestPathNameComparison(t *testing.T) {
	for _, tc := range []struct {
		name, filesystem, stored, query string
		sensitive, matches              bool
	}{
		{"APFS folded", "apfs", "File", "file", false, true},
		{"APFS sensitive", "apfs", "File", "file", true, false},
		{"APFS canonical sensitive", "apfs", "é", "e\u0301", true, true},
		{"APFS final sigma", "apfs", "Σ", "ς", false, true},
		{"APFS full fold", "apfs", "Straße", "STRASSE", false, true},
		{"HFS folded", "hfs", "File", "file", false, true},
		{"HFS sensitive", "hfs", "File", "file", true, false},
		{"HFS canonical", "hfs", "é", "e\u0301", true, true},
		{"HFS no modern expansion", "hfs", "Straße", "STRASSE", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := map[string]metatransport.Record{
				".":                  {Original: ".", Kind: "directory"},
				tc.stored:            {Original: tc.stored, Kind: "file"},
				"nested/" + tc.query: {Original: "nested/" + tc.query, Kind: "file"},
			}
			name, record, found, err := lookupPathComponent(records, ".", tc.query, &authorization.Mount{Filesystem: tc.filesystem, CaseSensitive: &tc.sensitive})
			if err != nil || found != tc.matches {
				t.Fatal(name, record, found, err)
			}
			if found && (name != tc.stored || record.Original != tc.stored) {
				t.Fatal("lookup did not retain original source spelling", name, record)
			}
		})
	}
}

func TestPathNameUnknownAndAmbiguousPolicy(t *testing.T) {
	insensitive, sensitive := false, true
	records := map[string]metatransport.Record{"File": {Original: "File"}, "file": {Original: "file"}}
	for _, mount := range []*authorization.Mount{nil, {}, {Filesystem: "apfs"}, {Filesystem: "unknown", CaseSensitive: &insensitive}} {
		if _, _, found, err := lookupPathComponent(records, ".", "file", mount); found || !errors.Is(err, ErrAuthority) {
			t.Fatal(found, err)
		}
	}
	for _, filesystem := range []string{"apfs", "hfs"} {
		for range 20 {
			if name, _, found, err := lookupPathComponent(records, ".", "file", &authorization.Mount{Filesystem: filesystem, CaseSensitive: &insensitive}); name != "" || found || !errors.Is(err, metatransport.ErrConflict) {
				t.Fatal("ambiguous context selected a record", name, found, err)
			}
		}
		if name, _, found, err := lookupPathComponent(records, ".", "file", &authorization.Mount{Filesystem: filesystem, CaseSensitive: &sensitive}); name != "file" || !found || err != nil {
			t.Fatal(name, found, err)
		}
	}
}

func TestPathBindingSnapshotsCasePolicy(t *testing.T) {
	s, _, _, capture, options := pathFixture(t)
	// Both nodes originally shared the caller's policy pointer. Altering either
	// after binding must not change lookup through the immutable PathContext.
	*capture.Nodes["."].Mount.CaseSensitive = true
	result, err := RecompressPath(t.Context(), s, "FILE", 2, options)
	if err != nil || !result.Published || result.Record.Original != "file" {
		t.Fatal(result, err)
	}
}

func TestPathMissingCaseObservationDoesNotPublish(t *testing.T) {
	s, _, _, capture, options := pathFixture(t)
	node := capture.Nodes["."]
	node.Mount.CaseSensitive = nil
	capture.Nodes["."] = node
	var err error
	options.Context, err = NewPathContext(t.Context(), s, 2, capture)
	if err != nil {
		t.Fatal(err)
	}
	result, err := RecompressPath(t.Context(), s, "file", 2, options)
	if result.Published || !errors.Is(err, ErrAuthority) {
		t.Fatal(result, err)
	}
	manifest, err := s.Load(t.Context())
	if err != nil || manifest.Generation != 2 {
		t.Fatal(manifest, err)
	}
}
