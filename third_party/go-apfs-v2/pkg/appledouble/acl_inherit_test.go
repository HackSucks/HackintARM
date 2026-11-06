package appledouble

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestNativeACLInheritanceAndRestoration(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/acl-inherit.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var fixture struct {
		HelperSHA256, SourceSHA256 string
		Records                    []struct {
			Name                     string
			Directory                bool
			Parent, Initial, Sidecar []byte
			Native                   struct {
				Parent, ParentAfter, Created, Restored           *string
				CreateCode, CreateErrno, UnpackCode, UnpackErrno int
				DestinationUnchanged                             bool
			}
		}
	}
	if err := json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile("../../testdata/appledouble/native/acl-inherit.c")
	if err != nil {
		t.Fatal(err)
	}
	// Git may check out C fixtures with CRLF on Windows; native provenance is LF.
	sum := sha256.Sum256(bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n")))
	if len(fixture.Records) != 850 || fixture.HelperSHA256 != hex.EncodeToString(sum[:]) || fixture.SourceSHA256 != "6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249" {
		t.Fatal("incomplete or changed native evidence")
	}
	parse := func(b []byte) *ACL {
		t.Helper()
		if b == nil {
			return nil
		}
		a, e := ParseACLText(b, nil)
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	decode := func(s *string) *ACL {
		t.Helper()
		if s == nil {
			return nil
		}
		b, e := hex.DecodeString(*s)
		if e != nil {
			t.Fatal(e)
		}
		a, e := ParseACLBinary(b)
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	equal := func(a *ACL, s *string) bool {
		t.Helper()
		if s == nil {
			return a == nil || (a.Flags == 0 && len(a.Entries) == 0)
		}
		if a == nil {
			return false
		}
		b, e := a.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(b) == *s
	}
	refused, restored := 0, 0
	for _, tc := range fixture.Records {
		t.Run(tc.Name, func(t *testing.T) {
			if !equal(parse(tc.Parent), tc.Native.Parent) {
				t.Fatal("native parent does not match supplied ACL")
			}
			got, e := InheritACL(parse(tc.Initial), decode(tc.Native.Parent), tc.Directory)
			if tc.Native.CreateCode != 0 {
				refused++
				if tc.Native.CreateCode != -1 || tc.Native.CreateErrno != 12 || !errors.Is(e, ErrACLInheritance) || got != nil {
					t.Fatalf("creation refusal differs: %v %v", got, e)
				}
				return
			}
			if e != nil || tc.Native.CreateErrno != 0 || !equal(got, tc.Native.Created) || !tc.Native.DestinationUnchanged || !reflect.DeepEqual(tc.Native.Parent, tc.Native.ParentAfter) {
				t.Fatalf("creation mismatch: %v %v", got, e)
			}
			if tc.Sidecar != nil {
				restored++
				f, e := Decode(tc.Sidecar)
				if e != nil {
					t.Fatal(e)
				}
				update, e := f.ACLUpdate(nil)
				if e != nil {
					t.Fatal(e)
				}
				want := decode(tc.Native.Created)
				if update.ACL != nil {
					want = update.ACL
				}
				if tc.Native.UnpackCode != 0 || tc.Native.UnpackErrno != 0 || !equal(want, tc.Native.Restored) {
					t.Fatal("AppleDouble replacement incorrectly retained/merged inheritance")
				}
			}
		})
	}
	if refused != 4 || restored != 22 {
		t.Fatalf("missing boundary/restoration cases: %d %d", refused, restored)
	}
}

func TestACLInheritanceOwnershipAndLimits(t *testing.T) {
	for _, directory := range []bool{false, true} {
		for _, parent := range []*ACL{nil, {}, {Flags: 1 << 17, Entries: []ACLEntry{{Flags: 1, Rights: 0xffffffff}}}} {
			got, e := InheritACL(nil, parent, directory)
			if got != nil || e != nil {
				t.Fatal(got, e)
			}
			got, e = InheritACL(&ACL{Flags: 0xffffffff}, parent, directory)
			if got == nil || e != nil || got.Flags != 0 || len(got.Entries) != 0 {
				t.Fatal(got, e)
			}
		}
		initial := &ACL{Flags: 1, Entries: []ACLEntry{{Principal: [16]byte{1}, Flags: 0xffff0001, Rights: 0xffffffff}, {Flags: 0x11}}}
		parent := &ACL{Flags: 1 << 17, Entries: []ACLEntry{{Principal: [16]byte{2}, Flags: 0xffff0162, Rights: 0xfedcba98}}}
		got, e := InheritACL(initial, parent, directory)
		if e != nil || got == nil || len(got.Entries) != 2 || got.Flags != 0 || got.Entries[0] != initial.Entries[0] {
			t.Fatal(got, e)
		}
		want := parent.Entries[0]
		want.Flags = (want.Flags | 0x10) &^ 0x100
		if !directory {
			want.Flags &^= 0x1e0
		}
		if got.Entries[1] != want {
			t.Fatal(got, want)
		}
		initial.Entries[0].Principal[0] = 3
		parent.Entries[0].Principal[0] = 4
		if got.Entries[0].Principal[0] != 1 || got.Entries[1].Principal[0] != 2 {
			t.Fatal("result aliases input")
		}
		got.Entries[0].Rights = 0
		got.Entries[1].Rights = 0
		if initial.Entries[0].Rights != 0xffffffff || parent.Entries[0].Rights != 0xfedcba98 {
			t.Fatal("input aliases result")
		}
	}
	oversized := &ACL{Entries: make([]ACLEntry, 129)}
	for _, pair := range [][2]*ACL{{oversized, nil}, {nil, oversized}, {oversized, oversized}} {
		if a, e := InheritACL(pair[0], pair[1], false); a != nil || !errors.Is(e, ErrACLInheritance) {
			t.Fatal(a, e)
		}
	}
	// Even discarded initial inherited entries consume the kernel allocation budget.
	initial := &ACL{Entries: make([]ACLEntry, 128)}
	for i := range initial.Entries {
		initial.Entries[i].Flags = 0x11
	}
	parent := &ACL{Entries: []ACLEntry{{Flags: 0x61}}}
	if a, e := InheritACL(initial, parent, false); a != nil || !errors.Is(e, ErrACLInheritance) {
		t.Fatal(a, e)
	}
	initial.Flags = 1 << 17
	if a, e := InheritACL(initial, parent, false); e != nil || a == nil || len(a.Entries) != 0 {
		t.Fatal(a, e)
	}
}

func FuzzACLInheritance(f *testing.F) {
	f.Add([]byte{1, 0x61, 0x11, 0xe2})
	f.Add([]byte{0, 0, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) == 0 || len(b) > 257 {
			return
		}
		initial, parent := &ACL{}, &ACL{}
		if b[0]&1 != 0 {
			initial.Flags = 1 << 17
		}
		for i, v := range b[1:] {
			e := ACLEntry{Principal: [16]byte{byte(i)}, Flags: uint32(v)<<1 | 1, Rights: uint32(v)}
			if i%2 == 0 {
				initial.Entries = append(initial.Entries, e)
			} else {
				parent.Entries = append(parent.Entries, e)
			}
		}
		beforeI, _ := initial.MarshalBinary()
		beforeP, _ := parent.MarshalBinary()
		got, err := InheritACL(initial, parent, b[0]&2 != 0)
		if err != nil {
			if !errors.Is(err, ErrACLInheritance) || got != nil {
				t.Fatal(got, err)
			}
			return
		}
		if got == nil || got.Flags != 0 || len(got.Entries) > 128 {
			t.Fatal(got)
		}
		a, _ := initial.MarshalBinary()
		p, _ := parent.MarshalBinary()
		if !bytes.Equal(a, beforeI) || !bytes.Equal(p, beforeP) {
			t.Fatal("inputs mutated")
		}
		raw, e := got.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := ParseACLBinary(raw)
		if e != nil {
			t.Fatal(e)
		}
		again, e := parsed.MarshalBinary()
		if e != nil || !bytes.Equal(raw, again) {
			t.Fatal("unstable result")
		}
	})
}
