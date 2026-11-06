package appledouble

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestNativeACLText(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/acl.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Records []struct {
			Name                      string
			Text, External, Canonical []byte
			Accepted                  bool
		}
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Records) != 59 {
		t.Fatalf("native ACL records: %d", len(f.Records))
	}
	for _, tc := range f.Records {
		t.Run(tc.Name, func(t *testing.T) {
			acl, err := ParseACLText(tc.Text, nil)
			if (err == nil) != tc.Accepted {
				t.Fatalf("native accepted=%t, Go error=%v", tc.Accepted, err)
			}
			if err != nil {
				return
			}
			raw, err := acl.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			text, err := acl.MarshalText()
			if err != nil || !bytes.Equal(text, tc.Canonical) {
				t.Fatalf("canonical text differs: %q / %q: %v", text, tc.Canonical, err)
			}
			if !bytes.Equal(raw, tc.External) {
				t.Fatalf("security bytes differ: got %x want %x", raw, tc.External)
			}
		})
	}
}

func TestACLSourceIdentityResolution(t *testing.T) {
	principal := [16]byte{1, 2, 3, 4}
	for _, tc := range []struct {
		kind, name, number string
		numeric            bool
		id                 uint32
	}{
		{"user", "alice", "ignored", false, 0},
		{"group", "staff", "20", false, 0},
		{"user", "", "+501suffix", true, 501},
		{"group", "", "-1", true, ^uint32(0)},
		{"group", "", "not-a-number", true, 0},
	} {
		t.Run(tc.kind+tc.name+tc.number, func(t *testing.T) {
			text := []byte(fmt.Sprintf("!#acl 1\n%s::%s:%s:allow:read\n", tc.kind, tc.name, tc.number))
			if _, err := ParseACLText(text, nil); !errors.Is(err, ErrACLResolver) {
				t.Fatal("missing resolver was not surfaced", err)
			}
			calls := 0
			a, err := ParseACLText(text, func(id ACLIdentity) ([16]byte, error) {
				calls++
				if id.Group != (tc.kind == "group") || id.Name != tc.name || (id.ID != nil) != tc.numeric {
					t.Fatal(id)
				}
				if id.ID != nil && *id.ID != tc.id {
					t.Fatal(*id.ID)
				}
				return principal, nil
			})
			if err != nil || calls != 1 || a.Entries[0].Principal != principal {
				t.Fatal(a, err, calls)
			}
			failure := errors.New("source directory lookup failed")
			if _, err := ParseACLText(text, func(ACLIdentity) ([16]byte, error) { return [16]byte{}, failure }); !errors.Is(err, failure) {
				t.Fatal(err)
			}
		})
	}
	// Native lookup precedence: UUID wins, and name prevents numeric fallback.
	text := []byte("!#acl 1\nuser:01234567-89AB-CDEF-0123-456789ABCDEF:alice:501:allow\n")
	if _, err := ParseACLText(text, func(ACLIdentity) ([16]byte, error) { t.Fatal("resolved redundant identity"); return [16]byte{}, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseACLText([]byte("!#acl 1\nugly::alice:501:allow\n"), nil); !errors.Is(err, ErrACLText) {
		t.Fatal(err)
	}
	a, err := ParseACLText([]byte("!#acl 1\nugly:::501:allow\n"), nil)
	if err != nil || a.Entries[0].Principal != [16]byte{} {
		t.Fatal(a, err)
	}
}

func TestACLNumericPrefixes(t *testing.T) {
	for _, tc := range []struct {
		text string
		base int
		want int64
	}{
		{"", 0, 0}, {"+", 0, 0}, {"-", 10, 0}, {" +1tail", 0, 1}, {"-1", 0, -1},
		{"0X1", 0, 1}, {"0xZ", 0, 0}, {"09", 0, 0}, {"01", 0, 1}, {"1_1", 0, 1},
		{"ZZ", 10, 0}, {"9223372036854775808", 10, 1<<63 - 1}, {"-9223372036854775809", 10, -1 << 63},
	} {
		t.Run(tc.text, func(t *testing.T) {
			if got := aclNumber(tc.text, tc.base); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestACLModelBounds(t *testing.T) {
	for _, a := range []*ACL{nil, {Entries: make([]ACLEntry, 129)}} {
		if _, err := a.MarshalBinary(); !errors.Is(err, ErrACLText) {
			t.Fatal(err)
		}
	}
	for _, text := range []string{"!#acl 1\n:uuid:::allow", "!#acl 1\nuser:::0:", "!#acl 1\nuser:01234567-89AB-CDEF-0123-456789ABCDEG:::allow:unknown", "!#acl 1\nuser:01234567-89AB-CDEF-0123-456789ABCDEF:::invalid:read"} {
		if _, err := ParseACLText([]byte(text), nil); !errors.Is(err, ErrACLText) {
			t.Fatal(text, err)
		}
	}
	// ACL interpretation is explicit; malformed policy payloads remain lossless.
	raw, err := FromXattrs(map[string][]byte{ACLTextName: []byte("INVALID")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	file, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(file.Xattrs()[ACLTextName]) != "INVALID" {
		t.Fatal("lost raw ACL policy record")
	}
}

func FuzzACLText(f *testing.F) {
	f.Add([]byte("!#acl 1\nuser:01234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n"))
	f.Add([]byte("!#acl 1 defer_inherit\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		acl, err := ParseACLText(data, nil)
		if err != nil {
			return
		}
		raw, err := acl.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(acl.Entries) > 128 || len(raw) != 44+24*len(acl.Entries) {
			t.Fatal("unbounded ACL")
		}
		// C-string termination must isolate the parsed ACL from trailing bytes.
		terminated := append(bytes.Clone(data), 0, 'x', ':', '\n')
		again, err := ParseACLText(terminated, nil)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := again.MarshalBinary()
		if err != nil || !bytes.Equal(raw, wire) {
			t.Fatal("NUL termination changed ACL", err)
		}
	})
}
