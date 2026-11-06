package appledouble

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestNativeFileSecurity(t *testing.T) {
	f, e := os.Open("../../testdata/appledouble/native/filesec.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	type metadata struct {
		Security              string
		UID, GID, Mode, Flags uint32
	}
	var fixture struct {
		HelperSHA256, CopyfileSHA256, XNUSHA256 string
		Conversions                             []struct {
			Name         string
			Disk, Darwin []byte
			Owner, Group string
		}
		Applications []struct {
			Name, Kind  string
			Mode, Flags uint32
			Text        []byte
			Before      metadata
			Request     string
			Native      struct {
				Code, Errno       int
				After             metadata
				IdentityUnchanged bool
			}
		}
	}
	if e = json.NewDecoder(z).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("../../testdata/appledouble/native/filesec.c")
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
	if hex.EncodeToString(hash[:]) != fixture.HelperSHA256 || fixture.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || fixture.XNUSHA256 != "6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249" || len(fixture.Conversions) != 72 || len(fixture.Applications) != 240 {
		t.Fatal("native provenance/corpus mismatch")
	}
	for _, tc := range fixture.Conversions {
		t.Run(tc.Name, func(t *testing.T) {
			disk, e := ParseFileSecurity(tc.Disk)
			if e != nil {
				t.Fatal(e)
			}
			native, e := ParseDarwinFileSecurity(tc.Darwin)
			if e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(disk, native) || hex.EncodeToString(disk.OwnerUUID[:]) != tc.Owner || hex.EncodeToString(disk.GroupUUID[:]) != tc.Group {
				t.Fatal("native semantic fields differ")
			}
			got, e := disk.MarshalDarwinBinary()
			if e != nil || !bytes.Equal(got, tc.Darwin) {
				t.Fatal("Darwin export", e)
			}
			got, e = native.MarshalBinary()
			if e != nil || !bytes.Equal(got, tc.Disk) {
				t.Fatal("disk export", e)
			}
		})
	}
	noops, writes, refusals := 0, 0, 0
	for _, tc := range fixture.Applications {
		t.Run(tc.Name, func(t *testing.T) {
			raw, e := hex.DecodeString(tc.Before.Security)
			if e != nil {
				t.Fatal(e)
			}
			dst, e := ParseDarwinFileSecurity(raw)
			if e != nil {
				t.Fatal(e)
			}
			file := File{Attrs: []Attr{{Name: ACLTextName, Value: tc.Text}}}
			update, e := file.ACLUpdate(nil)
			if e != nil {
				t.Fatal(e)
			}
			prepared, e := update.FileSecurity(dst)
			if e != nil {
				t.Fatal(e)
			}
			request := "-"
			if prepared != nil {
				raw, e = prepared.MarshalDarwinBinary()
				if e != nil {
					t.Fatal(e)
				}
				request = hex.EncodeToString(raw)
			}
			if request != tc.Request || !tc.Native.IdentityUnchanged {
				t.Fatal("request or identity mismatch")
			}
			if tc.Before.Mode&07777 != tc.Mode || tc.Before.Flags != tc.Flags {
				t.Fatal("fixture mode/flags not established")
			}
			after := tc.Native.After
			if after.UID != tc.Before.UID || after.GID != tc.Before.GID || after.Mode != tc.Before.Mode || after.Flags != tc.Before.Flags {
				t.Fatal("native ownership/mode/flags changed")
			}
			switch {
			case prepared == nil:
				noops++
				if tc.Native.Code != 0 || tc.Native.Errno != 0 || after != tc.Before {
					t.Fatal("no-op changed native destination")
				}
			case tc.Native.Code != 0:
				refusals++
				if tc.Native.Code != -1 || tc.Native.Errno != 1 || after != tc.Before {
					t.Fatal("unexpected native refusal")
				}
			default:
				writes++
				if tc.Native.Errno != 0 {
					t.Fatal("success errno")
				}
				raw, e = hex.DecodeString(after.Security)
				if e != nil {
					t.Fatal(e)
				}
				actual, e := ParseDarwinFileSecurity(raw)
				if e != nil {
					t.Fatal(e)
				}
				// Native filesystems may represent a cleared ACL as NOACL or zero entries.
				if actual.ACL == nil && len(prepared.ACL.Entries) == 0 && prepared.ACL.Flags == 0 {
					actual.ACL = &ACL{Entries: prepared.ACL.Entries}
				}
				actualBytes, actualErr := actual.MarshalDarwinBinary()
				expectedBytes, expectedErr := prepared.MarshalDarwinBinary()
				if actualErr != nil || expectedErr != nil || !bytes.Equal(actualBytes, expectedBytes) {
					t.Fatalf("native post-write security differs: %#v / %#v", actual, prepared)
				}
			}
		})
	}
	if noops != 120 || writes != 72 || refusals != 48 {
		t.Fatal("incomplete native application coverage", noops, writes, refusals)
	}
}

func TestFileSecurityValidation(t *testing.T) {
	for _, darwin := range []bool{false, true} {
		marshal := (*FileSecurity).MarshalBinary
		parse := ParseFileSecurity
		var order binary.ByteOrder = binary.BigEndian
		if darwin {
			marshal = (*FileSecurity).MarshalDarwinBinary
			parse = ParseDarwinFileSecurity
			order = binary.LittleEndian
		}
		source := &FileSecurity{ACL: &ACL{Entries: make([]ACLEntry, 128)}}
		good, e := marshal(source)
		if e != nil {
			t.Fatal(e)
		}
		for n := 0; n < len(good); n++ {
			if _, e := parse(good[:n]); !errors.Is(e, ErrFileSecurity) {
				t.Fatalf("accepted truncation %d", n)
			}
		}
		for _, count := range []uint32{129, 0xfffffffe, 0x80000000} {
			b := bytes.Clone(good)
			order.PutUint32(b[36:], count)
			if _, e := parse(b); !errors.Is(e, ErrFileSecurity) {
				t.Fatal("bad count", count, e)
			}
		}
		b := bytes.Clone(good)
		b[0] ^= 0xff
		if _, e := parse(b); !errors.Is(e, ErrFileSecurity) {
			t.Fatal("magic", e)
		}
		for _, bad := range []*FileSecurity{nil, {ACL: &ACL{}, NoACLFlags: [4]byte{1}}, {ACL: &ACL{Entries: make([]ACLEntry, 129)}}} {
			if _, e := marshal(bad); !errors.Is(e, ErrFileSecurity) {
				t.Fatal("bad model", e)
			}
		}
		absent := &FileSecurity{NoACLFlags: [4]byte{1, 2, 3, 4}, Trailing: []byte{5, 6}}
		b, e = marshal(absent)
		if e != nil {
			t.Fatal(e)
		}
		got, e := parse(b)
		if e != nil || !reflect.DeepEqual(got, absent) {
			t.Fatal("absent ACL lost bytes", got, e)
		}
		b[40] = 9
		b[44] = 9
		if got.NoACLFlags[0] != 1 || got.Trailing[0] != 5 {
			t.Fatal("parse aliases input")
		}
		got.Trailing[0] = 7
		if absent.Trailing[0] != 5 {
			t.Fatal("marshal aliases input")
		}
		clear, e := marshal(&FileSecurity{ACL: &ACL{}})
		if e != nil {
			t.Fatal(e)
		}
		got, e = parse(clear)
		if e != nil || got.ACL == nil {
			t.Fatal("clear became absent", e)
		}
	}
}
func TestFileSecurityReplacement(t *testing.T) {
	destination := &FileSecurity{OwnerUUID: [16]byte{1, 2}, GroupUUID: [16]byte{3, 4}, NoACLFlags: [4]byte{9}, Trailing: []byte{5, 6}}
	for _, update := range []ACLUpdate{{}, {Invalid: true}} {
		for _, dst := range []*FileSecurity{nil, destination} {
			got, e := update.FileSecurity(dst)
			if e != nil || got != nil {
				t.Fatal("no-op requires destination", e)
			}
		}
	}
	for _, tc := range []struct {
		u ACLUpdate
		d *FileSecurity
	}{{ACLUpdate{ACL: &ACL{}}, nil}, {ACLUpdate{ACL: &ACL{}, Invalid: true}, destination}, {ACLUpdate{ACL: &ACL{Entries: make([]ACLEntry, 129)}}, destination}} {
		if _, e := tc.u.FileSecurity(tc.d); !errors.Is(e, ErrFileSecurity) {
			t.Fatal("invalid replacement", e)
		}
	}
	acl := &ACL{Flags: 0x80000001, Entries: []ACLEntry{{Principal: [16]byte{8}, Flags: 1, Rights: 2}}}
	got, e := (ACLUpdate{ACL: acl}).FileSecurity(destination)
	if e != nil {
		t.Fatal(e)
	}
	if got.OwnerUUID != destination.OwnerUUID || got.GroupUUID != destination.GroupUUID || got.NoACLFlags != [4]byte{} || got.Trailing != nil || !reflect.DeepEqual(got.ACL, acl) {
		t.Fatal("replacement lost ownership or retained old data")
	}
	got.ACL.Entries[0].Rights = 99
	got.ACL.Flags = 0
	got.OwnerUUID[0] = 99
	if acl.Entries[0].Rights != 2 || acl.Flags != 0x80000001 || destination.OwnerUUID[0] != 1 {
		t.Fatal("replacement aliases source")
	}
	b, e := destination.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	b[4] = 99
	b[44] = 99
	if destination.OwnerUUID[0] != 1 || destination.Trailing[0] != 5 {
		t.Fatal("output aliases record")
	}
	raw, e := acl.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := ParseFileSecurity(raw)
	if e != nil {
		t.Fatal(e)
	}
	raw[44] = 99
	if parsed.ACL.Entries[0].Principal[0] != 8 {
		t.Fatal("entries alias input")
	}
}
func FuzzFileSecurity(f *testing.F) {
	for _, s := range []*FileSecurity{{}, {NoACLFlags: [4]byte{1, 2, 3, 4}, Trailing: []byte{5}}, {OwnerUUID: [16]byte{7}, ACL: &ACL{Entries: []ACLEntry{{Flags: 1, Rights: 2}}}}} {
		b, _ := s.MarshalBinary()
		f.Add(b)
		b, _ = s.MarshalDarwinBinary()
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		for _, parse := range []func([]byte) (*FileSecurity, error){ParseFileSecurity, ParseDarwinFileSecurity} {
			s, e := parse(b)
			if e != nil {
				continue
			}
			disk, e := s.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			native, e := s.MarshalDarwinBinary()
			if e != nil {
				t.Fatal(e)
			}
			a, e := ParseFileSecurity(disk)
			if e != nil {
				t.Fatal(e)
			}
			c, e := ParseDarwinFileSecurity(native)
			if e != nil || !reflect.DeepEqual(s, a) || !reflect.DeepEqual(a, c) {
				t.Fatal("security endian round trip", e)
			}
		}
	})
}
