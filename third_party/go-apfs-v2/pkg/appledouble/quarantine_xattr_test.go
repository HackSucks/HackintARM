package appledouble

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestNativeQuarantineXattr(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/quarantine-xattr.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Records []struct {
			Name              string
			Input, Serialized []byte
			Accepted          bool
		}
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Records) != 522 {
		t.Fatal("missing native xattr cases", len(f.Records))
	}
	for _, tc := range f.Records {
		t.Run(tc.Name, func(t *testing.T) {
			q, err := ParseQuarantineXattr(tc.Input)
			if (err == nil) != tc.Accepted {
				t.Fatalf("native accepted=%t Go=%v", tc.Accepted, err)
			}
			if err != nil {
				if !errors.Is(err, ErrQuarantine) {
					t.Fatal(err)
				}
				return
			}
			b, err := q.MarshalBinary()
			if err != nil || !bytes.Equal(b, tc.Serialized) {
				t.Fatalf("got %q want %q: %v", b, tc.Serialized, err)
			}
		})
	}
}

func TestQuarantineXattrProfilesAndLimits(t *testing.T) {
	raw := []byte("0081;12345678;Source;ID\x00")
	valid := append(append([]byte(nil), raw...), bytes.Repeat([]byte{'Z'}, MaxQuarantineXattrSize-len(raw))...)
	for _, profile := range []QuarantineProfile{QuarantineMacOS26, QuarantineMacOS27} {
		q, err := ParseQuarantineXattrWithProfile(valid, profile)
		if err != nil || q.Agent != "Source" {
			t.Fatal(q, err)
		}
		if _, err := ParseQuarantineXattrWithProfile(append(valid, 'Z'), profile); !errors.Is(err, ErrQuarantine) {
			t.Fatal("oversized stored value after NUL", err)
		}
		q, err = ParseQuarantineXattrWithProfile([]byte("2000;1;;"), profile)
		if (err == nil) != (profile == QuarantineMacOS27) {
			t.Fatal(profile, q, err)
		}
	}
	if _, err := ParseQuarantineXattrWithProfile(raw, 255); !errors.Is(err, ErrQuarantine) {
		t.Fatal(err)
	}
	q, err := ParseQuarantineXattr(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[14] = 'X'
	if q.Agent != "Source" {
		t.Fatal("model aliases input")
	}
	// Filesystem import can reject an oversized value whose envelope is valid.
	escaped := append([]byte("81;1;"), bytes.Repeat([]byte(`\x41`), 100)...)
	escaped = append(escaped, []byte(";ID")...)
	if _, err := ParseQuarantine(append([]byte("q/"), escaped...)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseQuarantineXattr(escaped); !errors.Is(err, ErrQuarantine) {
		t.Fatal(err)
	}
	// A captured source model can supply the existing ordered update API.
	f := &File{Attrs: []Attr{{Name: QuarantineName, Value: []byte("INVALID")}}}
	updates, err := f.QuarantineUpdates(QuarantineMacOS27, q)
	if err != nil || len(updates) != 1 || !updates[0].SourceOverride || updates[0].Invalid || *updates[0].Quarantine != *q {
		t.Fatal(updates, err)
	}
}

func FuzzQuarantineXattr(f *testing.F) {
	for _, b := range [][]byte{[]byte("0081;12345678;Source;ID"), []byte("81;1"), append([]byte("81;1;A;ID\x00"), make([]byte, 373)...), []byte("81;1;\\x41;\\x3b")} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, profile := range []QuarantineProfile{QuarantineMacOS26, QuarantineMacOS27} {
			q, err := ParseQuarantineXattrWithProfile(b, profile)
			if err != nil {
				continue
			}
			if len(b) > MaxQuarantineXattrSize {
				t.Fatal("accepted oversized stored value")
			}
			envelope, err := q.MarshalBinaryWithProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			again, err := ParseQuarantineWithProfile(envelope, profile)
			if err != nil || *again != *q {
				t.Fatal("imported state changed during envelope export", err)
			}
		}
	})
}
