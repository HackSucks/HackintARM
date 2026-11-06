package appledouble

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestNativeACLExternal(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/acl-external.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []struct {
			Name                  string
			Input, External, Text []byte
			Accepted              bool
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Records) != 34 {
		t.Fatal("missing native cases", len(fixture.Records))
	}
	for _, tc := range fixture.Records {
		t.Run(tc.Name, func(t *testing.T) {
			a, err := ParseACLBinary(tc.Input)
			if (err == nil) != tc.Accepted {
				t.Fatalf("native accepted=%t, Go error=%v", tc.Accepted, err)
			}
			if err != nil {
				return
			}
			b, err := a.MarshalBinary()
			if err != nil || !bytes.Equal(b, tc.External) {
				t.Fatalf("external differs: %x / %x: %v", b, tc.External, err)
			}
			text, err := a.MarshalText()
			if err != nil || !bytes.Equal(text, tc.Text) {
				t.Fatalf("text differs: %q / %q: %v", text, tc.Text, err)
			}
		})
	}
}

func TestACLBinaryBoundsAndOwnership(t *testing.T) {
	a := &ACL{Entries: []ACLEntry{{Principal: [16]byte{1, 2}, Flags: 1, Rights: 2}}}
	b, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(b); n++ {
		if _, err := ParseACLBinary(b[:n]); !errors.Is(err, ErrACLBinary) {
			t.Fatalf("accepted truncated length %d", n)
		}
	}
	decoded, err := ParseACLBinary(b)
	if err != nil {
		t.Fatal(err)
	}
	b[44] = 0xff
	if decoded.Entries[0].Principal != a.Entries[0].Principal {
		t.Fatal("input aliases parsed principal")
	}
	for _, a := range []*ACL{nil, {Entries: make([]ACLEntry, 129)}} {
		if _, err := a.MarshalText(); !errors.Is(err, ErrACLText) {
			t.Fatal(err)
		}
	}
}

func TestACLFormatSourceIdentity(t *testing.T) {
	a, err := ParseACLText([]byte("!#acl 1\nuser:01234567-89AB-CDEF-0123-456789ABCDEF:::deny:read\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		p     ACLPrincipal
		found bool
		want  string
	}{
		{"user", ACLPrincipal{Name: "alice", ID: 501}, true, "user:01234567-89AB-CDEF-0123-456789ABCDEF:alice:501:deny:read"},
		{"group", ACLPrincipal{Group: true, Name: "staff", ID: 20}, true, "group:01234567-89AB-CDEF-0123-456789ABCDEF:staff:20:deny:read"},
		{"signed-id-and-nul", ACLPrincipal{Name: "source\x00ignored", ID: ^uint32(0)}, true, "user:01234567-89AB-CDEF-0123-456789ABCDEF:source:-1:deny:read"},
		{"missing", ACLPrincipal{Group: true, Name: "ignored"}, false, "user:01234567-89AB-CDEF-0123-456789ABCDEF:::deny:read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			text, err := a.FormatText(func(uuid [16]byte) (ACLPrincipal, bool, error) {
				calls++
				if uuid != a.Entries[0].Principal {
					t.Fatal(uuid)
				}
				return tc.p, tc.found, nil
			})
			if err != nil || calls != 1 || string(text) != "!#acl 1\n"+tc.want+"\n" {
				t.Fatalf("%q calls=%d err=%v", text, calls, err)
			}
		})
	}
	failure := errors.New("source directory unavailable")
	if _, err := a.FormatText(func([16]byte) (ACLPrincipal, bool, error) { return ACLPrincipal{}, false, failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	a.Entries[0].Flags = 3
	if _, err := a.FormatText(func([16]byte) (ACLPrincipal, bool, error) {
		t.Fatal("looked up omitted entry")
		return ACLPrincipal{}, false, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func FuzzACLBinary(f *testing.F) {
	b, _ := (&ACL{Entries: []ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 2}}}).MarshalBinary()
	f.Add(b)
	f.Add([]byte{})
	f.Add(append(bytes.Clone(b), 1, 2, 3))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ParseACLBinary(b)
		if err != nil {
			return
		}
		external, err := a.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(external) > 44+128*24 || int(binary.BigEndian.Uint32(external[36:])) != len(a.Entries) {
			t.Fatal("unbounded external ACL")
		}
		// Import/export canonicalizes ignored ownership/trailing bytes exactly once.
		again, err := ParseACLBinary(external)
		if err != nil {
			t.Fatal(err)
		}
		stable, err := again.MarshalBinary()
		if err != nil || !bytes.Equal(stable, external) {
			t.Fatal("unstable external ACL", err)
		}
		text, err := a.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseACLText(text, nil)
		if err != nil {
			t.Fatal(err)
		}
		formatted, err := parsed.MarshalText()
		if err != nil || !bytes.Equal(formatted, text) {
			t.Fatal("unstable text", err)
		}
	})
}
