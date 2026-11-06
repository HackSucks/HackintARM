package hfsplus

import (
	"bytes"
	"os"
	"testing"
)

// TestCaseFoldOrdering pins the orderings that distinguish this table from a
// naive one. Each pair was observed on a case-insensitive volume macOS created;
// see scripts/derive-casefold.sh.
func TestCaseFoldOrdering(t *testing.T) {
	less := func(a, b string) bool {
		return compareCatalogKeysFolded(encodeCatalogKey(2, a), encodeCatalogKey(2, b)) < 0
	}

	// Case-insensitive: the same name in different cases is one name.
	if compareCatalogKeysFolded(encodeCatalogKey(2, "README"), encodeCatalogKey(2, "readme")) != 0 {
		t.Error("README and readme compare as different names")
	}
	if compareCatalogKeysFolded(encodeCatalogKey(2, "AbC.txt"), encodeCatalogKey(2, "aBc.TXT")) != 0 {
		t.Error("mixed-case spellings of one name compare as different")
	}

	// Ordering follows the folded value, so "B" sits between "a" and "c".
	if !less("a", "B") || !less("B", "c") {
		t.Error("uppercase does not sort at its lowercase position")
	}

	// Parent id dominates the name.
	if compareCatalogKeysFolded(encodeCatalogKey(2, "zzz"), encodeCatalogKey(3, "aaa")) >= 0 {
		t.Error("a lower parent id must sort first regardless of name")
	}

	// U+200C takes no part in the comparison at all.
	if compareCatalogKeysFolded(encodeCatalogKey(2, "a‌b"), encodeCatalogKey(2, "ab")) != 0 {
		t.Error("a zero-width non-joiner changed the name it appears in")
	}

	// Georgian is the case a table built from current Unicode gets wrong:
	// modern data maps U+10A0 to Nuskhuri U+2D00, HFS+ maps it to Mkhedruli
	// U+10D0. If this ever starts failing, the table was regenerated from
	// Unicode rather than from observation.
	if compareCatalogKeysFolded(encodeCatalogKey(2, "Ⴀ"), encodeCatalogKey(2, "ა")) != 0 {
		t.Error("Georgian capital U+10A0 does not fold to U+10D0")
	}

	// U+1E9E was added long after the table Apple froze, so it folds to itself
	// rather than to the sharp s a modern table would choose.
	if compareCatalogKeysFolded(encodeCatalogKey(2, "ẞ"), encodeCatalogKey(2, "ß")) == 0 {
		t.Error("U+1E9E folded to U+00DF; HFS+ predates that mapping")
	}
}

// TestCaseInsensitiveVolume writes a case-insensitive volume and reads it back,
// checking the header identifies it and that lookups ignore case.
func TestCaseInsensitiveVolume(t *testing.T) {
	root := &Entry{Children: []*Entry{
		{Name: "ReadMe.txt", Mode: 0o644, Data: []byte("contents\n")},
		{Name: "Ünïcødé.txt", Mode: 0o644, Data: []byte("unicode\n")},
		{Name: "Sub", Mode: os.ModeDir | 0o755, Children: []*Entry{
			{Name: "Nested.txt", Mode: 0o644, Data: []byte("nested\n")},
		}},
	}}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "CI", root, &CreateOptions{CaseInsensitive: true}); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}

	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if v.CaseSensitive() {
		t.Error("the volume reports itself case-sensitive")
	}
	if got := v.Header().Signature; got != HFSPlusSigWord {
		t.Errorf("signature = %v, want H+", got)
	}
	if got := v.Header().Version; got != HFSPlusVersion {
		t.Errorf("version = %d, want %d", got, HFSPlusVersion)
	}

	for _, name := range []string{"ReadMe.txt", "readme.txt", "README.TXT"} {
		got, err := v.ReadFile(name)
		if err != nil || string(got) != "contents\n" {
			t.Errorf("ReadFile(%q) = %q, err=%v", name, got, err)
		}
	}
	if _, err := v.ReadFile("sub/nested.txt"); err != nil {
		t.Errorf("case-insensitive lookup through a directory: %v", err)
	}
}

// TestCaseSensitiveRemainsDefault guards the default: an image built without
// the option must still be HFSX, so existing output does not change.
func TestCaseSensitiveRemainsDefault(t *testing.T) {
	root := &Entry{Children: []*Entry{{Name: "A.txt", Mode: 0o644, Data: []byte("x\n")}}}
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "CS", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !v.CaseSensitive() {
		t.Error("the default volume is no longer case-sensitive")
	}
	if got := v.Header().Signature; got != HFSXSigWord {
		t.Errorf("signature = %v, want HX", got)
	}
}
