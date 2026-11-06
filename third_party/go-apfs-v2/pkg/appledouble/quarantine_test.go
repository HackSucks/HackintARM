package appledouble

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNativeQuarantine(t *testing.T) {
	for _, profile := range []struct {
		name, file string
		value      QuarantineProfile
	}{{"macos27", "quarantine.json", QuarantineMacOS27}, {"macos26", "quarantine-macos26.json", QuarantineMacOS26}} {
		t.Run(profile.name, func(t *testing.T) {
			raw, err := os.ReadFile("../../testdata/appledouble/native/" + profile.file)
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
			if len(f.Records) != 434 {
				t.Fatal("missing native cases", len(f.Records))
			}
			for _, tc := range f.Records {
				t.Run(tc.Name, func(t *testing.T) {
					q, err := ParseQuarantineWithProfile(tc.Input, profile.value)
					if (err == nil) != tc.Accepted {
						t.Fatalf("native accepted=%t, Go=%v", tc.Accepted, err)
					}
					if err != nil {
						return
					}
					b, err := q.MarshalBinaryWithProfile(profile.value)
					if err != nil || !bytes.Equal(b, tc.Serialized) {
						t.Fatalf("got %q, want %q: %v", b, tc.Serialized, err)
					}
				})
			}
		})
	}
}

func TestQuarantineModelBounds(t *testing.T) {
	for _, q := range []*Quarantine{nil, {Flags: 0x4000}, {Agent: string(make([]byte, 256))}, {Identifier: string(make([]byte, 65))}, {Agent: "a\x00b"}, {Identifier: "a\x00b"}} {
		if _, err := q.MarshalBinary(); !errors.Is(err, ErrQuarantine) {
			t.Fatal(q, err)
		}
	}
	q := &Quarantine{}
	b, err := q.MarshalBinary()
	if err != nil || string(b) != "q/0001;00000000;;\x00" {
		t.Fatal(string(b), err)
	}
	q = &Quarantine{Flags: 0x3fff, Timestamp: ^uint32(0), Agent: strings.Repeat("\xff", 255), Identifier: strings.Repeat("\xfe", 64)}
	b, err = q.MarshalBinary()
	if err != nil || len(b) != 1294 {
		t.Fatal(len(b), err)
	}
	decoded, err := ParseQuarantine(b)
	if err != nil || *decoded != *q {
		t.Fatal(decoded, err)
	}
	b[2] = '0'
	if decoded.Flags != 0x3fff {
		t.Fatal("parsed result aliases input")
	}
	// Generic byte decoding must retain rejected policy records for inspection.
	raw, err := FromXattrs(map[string][]byte{QuarantineName: []byte("INVALID")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	f, err := Decode(raw)
	if err != nil || string(f.Xattrs()[QuarantineName]) != "INVALID" {
		t.Fatal(f, err)
	}
}
func FuzzQuarantine(f *testing.F) {
	for _, s := range []string{"q/0081;12345678;Probe;ID\x00", "q/81;1", "q/81;1;a\\x00b;", "q/81;1;a\\x5c;ID"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		for _, profile := range []QuarantineProfile{QuarantineMacOS26, QuarantineMacOS27} {
			q, err := ParseQuarantineWithProfile(b, profile)
			if err != nil {
				continue
			}
			encoded, err := q.MarshalBinaryWithProfile(profile)
			if err != nil || len(encoded) > 1294 {
				t.Fatal(len(encoded), err)
			}
			again, err := ParseQuarantineWithProfile(encoded, profile)
			if err != nil || *again != *q {
				t.Fatal(again, q, err)
			}
			stable, err := again.MarshalBinaryWithProfile(profile)
			if err != nil || !bytes.Equal(encoded, stable) {
				t.Fatal("unstable canonicalization", err)
			}
		}
	})
}

func TestQuarantineProfiles(t *testing.T) {
	if _, err := ParseQuarantineWithProfile([]byte("q/81;1;;"), 255); !errors.Is(err, ErrQuarantine) {
		t.Fatal(err)
	}
	if _, err := (&Quarantine{}).MarshalBinaryWithProfile(255); !errors.Is(err, ErrQuarantine) {
		t.Fatal(err)
	}
	for _, p := range []QuarantineProfile{QuarantineMacOS26, QuarantineMacOS27} {
		if _, err := (*Quarantine)(nil).MarshalBinaryWithProfile(p); !errors.Is(err, ErrQuarantine) {
			t.Fatal(err)
		}
		for _, flags := range []uint32{0, 0x1fff, 0x2000, 0x3fff, 0x4000} {
			q := &Quarantine{Flags: flags}
			b, err := q.MarshalBinaryWithProfile(p)
			accepted := flags <= 0x1fff || (p == QuarantineMacOS27 && flags <= 0x3fff)
			if (err == nil) != accepted {
				t.Fatal(p, flags, err)
			}
			if err != nil {
				continue
			}
			got, err := ParseQuarantineWithProfile(b, p)
			want := flags
			if want == 0 {
				want = 1
			}
			if err != nil || got.Flags != want {
				t.Fatal(got, err)
			}
		}
	}
}
