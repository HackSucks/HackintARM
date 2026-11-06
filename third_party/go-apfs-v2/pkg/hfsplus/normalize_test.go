package hfsplus

import (
	"bytes"
	"testing"
)

// TestNormalizeName pins the cases that distinguish this from plain NFD, each
// observed on a volume macOS created; see scripts/derive-normalization.sh.
func TestNormalizeName(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []rune
	}{
		{"precomposed letter decomposes", "ü", []rune{0x0075, 0x0308}},
		{"a whole name decomposes", "café", []rune{'c', 'a', 'f', 0x0065, 0x0301}},
		{"ascii is untouched", "hello.txt", []rune("hello.txt")},
		// No canonical decomposition at all, so nothing to do.
		{"o with stroke is untouched", "ø", []rune{0x00F8}},
		// Excluded deliberately: decomposing a CJK compatibility ideograph
		// would lose the distinction it exists to record.
		{"cjk compatibility is excluded", "豈", []rune{0xF900}},
		// Excluded because its decomposition postdates the behaviour HFS+
		// froze, the same reason U+1E9E folds to itself.
		{"balinese is excluded", "ᬆ", []rune{0x1B06}},
		{"angle bracket is excluded", "〈", []rune{0x2329}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := []rune(normalizeName(tc.in))
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeName(%q) = %04X, want %04X", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizeName(%q) = %04X, want %04X", tc.in, got, tc.want)
				}
			}
		})
	}
}

// TestNormalizeNameIsIdempotent guards the property the writer relies on: a
// name already in stored form must survive unchanged, or normalizing twice
// would drift.
func TestNormalizeNameIsIdempotent(t *testing.T) {
	for _, in := range []string{"ü", "café", "hello.txt", "豈", "日本語", "Ω"} {
		once := normalizeName(in)
		if twice := normalizeName(once); twice != once {
			t.Errorf("normalizeName(%q) is not idempotent: %q then %q", in, once, twice)
		}
	}
}

// TestWritePrecomposedNamesAreFound is the bug this fixes: a name given
// precomposed was stored precomposed, which is a form macOS does not look for.
func TestWritePrecomposedNamesAreFound(t *testing.T) {
	root := &Entry{Children: []*Entry{
		{Name: "ünïcødé.txt", Mode: 0o644, Data: []byte("accented\n")},
		{Name: "café", Mode: 0o644, Data: []byte("cafe\n")},
		{Name: "plain.txt", Mode: 0o644, Data: []byte("plain\n")},
	}}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "NORM", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The stored name is decomposed...
	entries, err := v.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var storedAccented string
	for _, e := range entries {
		if len(e.Name()) > 4 && e.Name() != "plain.txt" && e.Name() != "café" {
			storedAccented = e.Name()
		}
	}
	if storedAccented == "ünïcødé.txt" {
		t.Error("the name was stored precomposed; macOS would not find it")
	}

	// ...and both spellings resolve, which is what a caller needs.
	for _, name := range []string{"ünïcødé.txt", normalizeName("ünïcødé.txt"), "café", normalizeName("café")} {
		if _, err := v.ReadFile(name); err != nil {
			t.Errorf("ReadFile(%q): %v", name, err)
		}
	}
}

// TestWriteNormalizationIsDeterministic checks normalizing names has not cost
// the writer its byte-for-byte reproducibility.
func TestWriteNormalizationIsDeterministic(t *testing.T) {
	build := func() []byte {
		root := &Entry{Children: []*Entry{
			{Name: "ünïcødé.txt", Mode: 0o644, Data: []byte("a\n")},
			{Name: "café", Mode: 0o644, Data: []byte("b\n")},
			{Name: "日本語.txt", Mode: 0o644, Data: []byte("c\n")},
		}}
		w := &memWriterAt{}
		if err := CreateImage(w, 0, "DET", root, nil); err != nil {
			t.Fatalf("CreateImage: %v", err)
		}
		return w.b
	}
	if !bytes.Equal(build(), build()) {
		t.Error("two runs over the same names produced different images")
	}
}
