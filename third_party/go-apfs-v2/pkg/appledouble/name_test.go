package appledouble

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"testing"
)

func TestNativeNameRecords(t *testing.T) {
	b, err := os.ReadFile("../../testdata/appledouble/native/names.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []struct {
			Name       string
			Raw        []byte
			Accepted   bool
			Attributes []struct{ Name, Value []byte }
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Records) != 14 {
		t.Fatal("required native name observations missing")
	}
	for _, tc := range fixture.Records {
		t.Run(tc.Name, func(t *testing.T) {
			f, err := Decode(tc.Raw)
			if (err == nil) != tc.Accepted {
				t.Fatalf("Decode error=%v, native acceptance=%t", err, tc.Accepted)
			}
			if !tc.Accepted {
				return
			}
			if len(f.Attrs) != len(tc.Attributes) {
				t.Fatal("native attribute count differs")
			}
			for i, a := range tc.Attributes {
				if !bytes.Equal([]byte(f.Attrs[i].Name), a.Name) || !bytes.Equal(f.Attrs[i].Value, a.Value) {
					t.Fatal("logical name/value differs from native")
				}
			}
			canonical, err := f.Encode()
			if err != nil {
				t.Fatal(err)
			}
			again, err := Decode(canonical)
			if err != nil {
				t.Fatal(err)
			}
			if len(again.Attrs) != len(f.Attrs) {
				t.Fatal("canonical count changed")
			}
			for i, a := range f.Attrs {
				if again.Attrs[i].Name != a.Name || !bytes.Equal(again.Attrs[i].Value, a.Value) {
					t.Fatal("canonical data changed")
				}
			}
		})
	}
}

func TestEncodeRejectsInvalidUTF8Names(t *testing.T) {
	for _, name := range []string{string([]byte{255}), string([]byte{'x', 195}), "a\x00b"} {
		if _, err := (&File{Attrs: []Attr{{Name: name}}}).Encode(); err == nil {
			t.Fatalf("accepted name %q", name)
		}
	}
}

func TestEmbeddedNULKeepsDeclaredRecordStep(t *testing.T) {
	raw := craftPaddedName("a\x00z", 8, []byte("first"), "bbb", []byte("second"))
	f, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Attrs) != 2 || f.Attrs[0].Name != "a" || string(f.Attrs[0].Value) != "first" || f.Attrs[1].Name != "bbb" || string(f.Attrs[1].Value) != "second" {
		t.Fatal("C-string name handling changed record alignment", f.Attrs)
	}
}

func TestContainsRangeWithoutOverflow(t *testing.T) {
	for _, tc := range []struct {
		size, offset, length int
		want                 bool
	}{
		{0, 0, 0, true}, {10, 10, 0, true}, {10, 9, 1, true}, {10, 10, 1, false},
		{10, -1, 1, false}, {10, 0, -1, false}, {10, 11, 0, false},
		{math.MaxInt, math.MaxInt - 1, 1, true}, {math.MaxInt, math.MaxInt - 1, 2, false},
		{math.MaxInt, math.MaxInt, math.MaxInt, false},
	} {
		if got := containsRange(tc.size, tc.offset, tc.length); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
