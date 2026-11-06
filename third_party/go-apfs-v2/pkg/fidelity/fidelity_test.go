package fidelity

import (
	"reflect"
	"testing"
)

func TestZeroReportIsLossless(t *testing.T) {
	var r Report
	if !r.Lossless() {
		t.Error("the zero Report is not lossless")
	}
	if r.Total() != 0 || r.EntriesSkipped() != 0 || len(r.Kinds()) != 0 {
		t.Error("the zero Report reports losses")
	}
}

// TestNilReportIsUsable matters because the walks take a *Report that callers
// who do not want one leave nil. Every method must tolerate that rather than
// forcing a nil check at each call site.
func TestNilReportIsUsable(t *testing.T) {
	var r *Report
	r.Add(Xattr, "some/path") // must not panic
	if !r.Lossless() || r.Total() != 0 || r.Count(Xattr) != 0 {
		t.Error("a nil Report reports losses")
	}
	if r.Kinds() != nil || r.Examples(Xattr) != nil {
		t.Error("a nil Report returned non-nil detail")
	}
	if json := r.JSON(); json["lossless"] != true {
		t.Error("a nil Report's JSON does not report lossless")
	}
}

func TestReportCounts(t *testing.T) {
	var r Report
	r.Add(SpecialFile, "pipe")
	r.Add(Xattr, "a.txt")
	r.Add(Xattr, "a.txt")
	r.Add(Xattr, "b.txt")
	r.Add(HardLink, "linked.txt")

	if got := r.Count(Xattr); got != 3 {
		t.Errorf("Count(Xattr) = %d, want 3", got)
	}
	if got := r.Total(); got != 5 {
		t.Errorf("Total = %d, want 5", got)
	}
	if r.Lossless() {
		t.Error("a report with losses claims to be lossless")
	}

	// Only entries omitted altogether count here: a file written without its
	// extended attributes is still in the volume.
	if got := r.EntriesSkipped(); got != 1 {
		t.Errorf("EntriesSkipped = %d, want 1 (the special file only)", got)
	}

	want := []Kind{SpecialFile, Xattr, HardLink}
	if got := r.Kinds(); !reflect.DeepEqual(got, want) {
		t.Errorf("Kinds = %v, want %v (declaration order)", got, want)
	}
}

// TestExamplesAreCapped guards against a tree with an attribute on every file
// producing one warning per file, which would bury the summary.
func TestExamplesAreCapped(t *testing.T) {
	var r Report
	for i := range ExampleLimit * 3 {
		r.Add(Xattr, string(rune('a'+i%26)))
	}
	if got := len(r.Examples(Xattr)); got != ExampleLimit {
		t.Errorf("retained %d examples, want the cap of %d", got, ExampleLimit)
	}
	if got := r.Count(Xattr); got != ExampleLimit*3 {
		t.Errorf("Count = %d, want %d; capping examples must not cap the count", got, ExampleLimit*3)
	}
}

// TestJSONShapeIsStable pins the schema: every key is always present, so a
// consumer can rely on the shape rather than testing for absence.
func TestJSONShapeIsStable(t *testing.T) {
	var empty Report
	json := empty.JSON()

	for _, key := range Keys() {
		if _, ok := json[key]; !ok {
			t.Errorf("key %q missing from JSON()", key)
		}
	}
	if len(json) != len(Keys()) {
		t.Errorf("JSON() has %d keys, want %d; a new key needs adding to Keys()", len(json), len(Keys()))
	}
	if json["lossless"] != true {
		t.Error("an empty report is not reported as lossless")
	}

	var lossy Report
	lossy.Add(ResourceFork, "app/Contents/MacOS/binary")
	if got := lossy.JSON()["resourceForksDropped"]; got != 1 {
		t.Errorf("resourceForksDropped = %v, want 1", got)
	}
	if lossy.JSON()["lossless"] != false {
		t.Error("a report with losses is reported as lossless")
	}
}

// TestKindMetadataIsComplete catches a kind added to the enum but not to the
// table, which would otherwise surface as "unknown" in output.
func TestKindMetadataIsComplete(t *testing.T) {
	for _, k := range allKinds {
		if k.Key() == "unknown" || k.String() == "unknown" || k.Note() == "dropped" {
			t.Errorf("kind %d has no entry in the metadata table", int(k))
		}
	}
	seen := map[string]bool{}
	for _, k := range allKinds {
		if seen[k.Key()] {
			t.Errorf("duplicate JSON key %q", k.Key())
		}
		seen[k.Key()] = true
	}
	if len(allKinds) != len(kinds) {
		t.Errorf("allKinds has %d entries, the metadata table %d; they must agree", len(allKinds), len(kinds))
	}
}

// TestLostPhrasingReadsAsAPredicate guards the per-entry line, which is printed
// as "<path>: <Lost()> (<detail>)". Compression is the kind that breaks the
// default phrasing: "compressed file not carried across" says the file was
// dropped, when in fact only its compression was and the content is all there.
func TestLostPhrasingReadsAsAPredicate(t *testing.T) {
	for _, k := range allKinds {
		if k.Lost() == "not carried across" {
			t.Errorf("kind %q has no per-entry phrasing", k)
		}
	}

	if got, want := Compression.Lost(), "compression not carried across; the file itself is written out in full"; got != want {
		t.Errorf("Compression.Lost() = %q, want %q", got, want)
	}
	// The default still applies to the kinds it suits.
	if got, want := Xattr.Lost(), "extended attribute not carried across"; got != want {
		t.Errorf("Xattr.Lost() = %q, want %q", got, want)
	}
}

// TestCompressionIsNotAContentLoss records why Compression is its own kind
// rather than a Xattr or a ResourceFork: nothing was lost, so a report saying
// content was dropped would be untrue.
func TestCompressionIsNotAContentLoss(t *testing.T) {
	if Compression == Xattr || Compression == ResourceFork {
		t.Fatal("Compression must be distinct from the kinds that mean content was lost")
	}
	if got := Compression.Key(); got != "compressionNotPreserved" {
		t.Errorf("JSON key = %q, want compressionNotPreserved", got)
	}
}
