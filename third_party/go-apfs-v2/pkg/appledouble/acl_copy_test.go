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

type copyMetadata struct {
	ACL                   *string
	UID, GID, Mode, Flags uint32
}

func TestNativeACLCopy(t *testing.T) {
	f, e := os.Open("../../testdata/appledouble/native/acl-copy.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct {
		HelperSHA256, SourceSHA256 string
		Models                     []struct {
			Name                string
			Source, Destination []byte
			Native              struct {
				Code, Errno, Captures, Writes int
				ACL, SourceCache              *string
			}
		}
		Applications []struct {
			Name, Kind, Source, Destination string
			Native                          struct {
				Code, Errno                              int
				Filesystem                               string
				SourceBefore, SourceAfter, Before, After copyMetadata
				IdentityUnchanged, PayloadUnchanged      bool
			}
		}
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("../../testdata/appledouble/native/acl-copy.c")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
	if hex.EncodeToString(h[:]) != corpus.HelperSHA256 || corpus.SourceSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || len(corpus.Models) != 256 || len(corpus.Applications) != 288 {
		t.Fatal("native corpus/source provenance")
	}
	decode := func(b []byte) *ACL {
		if b == nil {
			return nil
		}
		a, e := ParseACLBinary(b)
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	decodeHex := func(s *string) *ACL {
		if s == nil {
			return nil
		}
		b, e := hex.DecodeString(*s)
		if e != nil {
			t.Fatal(e)
		}
		return decode(b)
	}
	encode := func(a *ACL) *string {
		if a == nil {
			return nil
		}
		b, e := a.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		s := hex.EncodeToString(b)
		return &s
	}
	modelFailures, copyFailures := 0, 0
	seen := map[string]bool{}
	for _, tc := range corpus.Models {
		t.Run("model/"+tc.Name, func(t *testing.T) {
			if seen[tc.Name] {
				t.Fatal("duplicate model")
			}
			seen[tc.Name] = true
			source, destination := decode(tc.Source), decode(tc.Destination)
			got, e := CopyACL(source, destination)
			if tc.Native.Captures != 1 {
				t.Fatal("native capture count")
			}
			if tc.Native.Code == 0 {
				if e != nil || tc.Native.Errno != 0 || tc.Native.Writes != 1 || !reflect.DeepEqual(encode(got), tc.Native.ACL) || !reflect.DeepEqual(tc.Native.SourceCache, tc.Native.ACL) {
					t.Fatal("native policy differs", e)
				}
			} else {
				modelFailures++
				if !errors.Is(e, ErrACLCopy) || got != nil || tc.Native.Code != -1 || tc.Native.Errno != 12 || tc.Native.Writes != 0 || tc.Native.ACL != nil || !reflect.DeepEqual(tc.Native.SourceCache, encode(source)) {
					t.Fatal("native limit/error/cache differs", e)
				}
			}
			// Native input files are binary so unknown flags and entry kinds are retained.
			if !reflect.DeepEqual(encode(source), encode(decode(tc.Source))) || !reflect.DeepEqual(encode(destination), encode(decode(tc.Destination))) {
				t.Fatal("inputs mutated")
			}
		})
	}
	for _, tc := range corpus.Applications {
		t.Run("copy/"+tc.Name, func(t *testing.T) {
			if seen[tc.Name] {
				t.Fatal("duplicate application")
			}
			seen[tc.Name] = true
			n := tc.Native
			got, e := CopyACL(decodeHex(n.SourceBefore.ACL), decodeHex(n.Before.ACL))
			if n.Filesystem != "apfs" || !n.IdentityUnchanged || !n.PayloadUnchanged || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) {
				t.Fatal("source, identity or payload changed")
			}
			after := n.After
			after.ACL = n.Before.ACL
			if !reflect.DeepEqual(after, n.Before) {
				t.Fatal("ownership/mode/flags changed")
			}
			if n.Code == 0 {
				if e != nil || n.Errno != 0 {
					t.Fatal("native success differs", e)
				}
				want := encode(got)
				// The actual filesystem can normalize a present zero-entry ACL to absence.
				if got != nil && len(got.Entries) == 0 && n.After.ACL == nil {
					want = nil
				}
				if !reflect.DeepEqual(want, n.After.ACL) {
					t.Fatal("native copied ACL differs")
				}
			} else {
				copyFailures++
				if !errors.Is(e, ErrACLCopy) || got != nil || n.Code != -1 || n.Errno != 12 || !reflect.DeepEqual(n.Before, n.After) {
					t.Fatal("native failed copy differs", e)
				}
			}
		})
	}
	if modelFailures != 21 || copyFailures != 18 {
		t.Fatal("native boundary coverage", modelFailures, copyFailures)
	}
}

func TestCopyACLBoundsAndOwnership(t *testing.T) {
	for _, pair := range [][2]*ACL{{{Entries: make([]ACLEntry, 129)}, nil}, {nil, {Entries: make([]ACLEntry, 129)}}} {
		got, e := CopyACL(pair[0], pair[1])
		if got != nil || !errors.Is(e, ErrACLCopy) {
			t.Fatal("oversized input accepted")
		}
	}
	source := &ACL{Flags: 0xffffffff, Entries: []ACLEntry{{Flags: 1, Rights: 3, Principal: [16]byte{4}}, {Flags: 17}}}
	destination := &ACL{Flags: 0xffffffff, Entries: []ACLEntry{{Flags: 2}, {Flags: 18, Rights: 5, Principal: [16]byte{6}}}}
	got, e := CopyACL(source, destination)
	if e != nil || got.Flags != 0 || !reflect.DeepEqual(got.Entries, []ACLEntry{source.Entries[0], destination.Entries[1]}) {
		t.Fatal(got, e)
	}
	got.Entries[0].Principal[0] = 99
	got.Entries[1].Rights = 99
	if source.Entries[0].Principal[0] != 4 || destination.Entries[1].Rights != 5 {
		t.Fatal("result aliases input")
	}
	got, e = CopyACL(source, destination)
	if e != nil {
		t.Fatal(e)
	}
	source.Entries[0].Flags = 99
	destination.Entries[1].Flags = 99
	if got.Entries[0].Flags != 1 || got.Entries[1].Flags != 18 {
		t.Fatal("input aliases result")
	}
	// All 256 input entries fit when 128 are selected; no creation-style budget.
	src, dst := &ACL{Entries: make([]ACLEntry, 128)}, &ACL{Entries: make([]ACLEntry, 128)}
	for i := range src.Entries {
		src.Entries[i].Flags = 17
		dst.Entries[i].Flags = 17
	}
	got, e = CopyACL(src, dst)
	if e != nil || len(got.Entries) != 128 {
		t.Fatal("discarded entries counted", e)
	}
	for _, pair := range [][2]*ACL{{nil, nil}, {nil, {}}, {{}, nil}} {
		got, e := CopyACL(pair[0], pair[1])
		if e != nil || (got == nil) != (pair[0] == nil && pair[1] == nil) {
			t.Fatal("nil/empty distinction")
		}
	}
	// AppleDouble restoration is replacement even after an ordinary ACL copy.
	replacement := &ACL{Flags: 1 << 17, Entries: []ACLEntry{{Flags: 1, Rights: 9}}}
	sec, e := (ACLUpdate{ACL: replacement}).FileSecurity(&FileSecurity{ACL: got})
	if e != nil || !reflect.DeepEqual(sec.ACL, replacement) {
		t.Fatal("replacement became a merge", e)
	}
}

func FuzzCopyACL(f *testing.F) {
	for _, n := range []int{0, 1, 64, 128} {
		a := &ACL{Entries: make([]ACLEntry, n)}
		for i := range a.Entries {
			a.Entries[i].Flags = uint32(i%2)*16 + 1
		}
		b, _ := a.MarshalBinary()
		f.Add(b, b, false, false)
	}
	f.Add([]byte{}, []byte{}, true, true)
	f.Fuzz(func(t *testing.T, a, b []byte, nilSource, nilDestination bool) {
		if len(a) > 3116 || len(b) > 3116 {
			return
		}
		parse := func(b []byte, absent bool) (*ACL, error) {
			if absent {
				return nil, nil
			}
			return ParseACLBinary(b)
		}
		src, e := parse(a, nilSource)
		if e != nil {
			return
		}
		dst, e := parse(b, nilDestination)
		if e != nil {
			return
		}
		before := func(acl *ACL) []byte {
			if acl == nil {
				return nil
			}
			b, e := acl.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			return b
		}
		sb, db := before(src), before(dst)
		got, e := CopyACL(src, dst)
		if !bytes.Equal(sb, before(src)) || !bytes.Equal(db, before(dst)) {
			t.Fatal("input mutated")
		}
		if e != nil {
			if !errors.Is(e, ErrACLCopy) || got != nil {
				t.Fatal("error contract")
			}
			return
		}
		if got == nil {
			if src != nil || dst != nil {
				t.Fatal("lost empty result")
			}
			return
		}
		if got.Flags != 0 || len(got.Entries) > 128 {
			t.Fatal("result flags/bound")
		}
		encoded := before(got)
		round, e := ParseACLBinary(encoded)
		if e != nil || !bytes.Equal(before(round), encoded) {
			t.Fatal("result wire roundtrip")
		}
		// Once all retained source entries are made inherited, none can survive.
		if src != nil {
			for i := range src.Entries {
				src.Entries[i].Flags |= 16
			}
		}
		if dst != nil {
			for i := range dst.Entries {
				dst.Entries[i].Flags &^= 16
			}
		}
		empty, e := CopyACL(src, dst)
		if e != nil || empty == nil || len(empty.Entries) != 0 {
			t.Fatal("discard policy", e)
		}
		if !bytes.Equal(before(got), encoded) {
			t.Fatal("result aliases input")
		}
	})
}
