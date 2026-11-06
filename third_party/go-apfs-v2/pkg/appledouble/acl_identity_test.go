package appledouble

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
)

func TestNativeACLIdentitySnapshots(t *testing.T) {
	f, e := os.Open("../../testdata/appledouble/native/acl-identities.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var fixture struct {
		HelperSHA256, ACLHelperSHA256, SourceSHA256 string
		Records                                     []struct {
			Name                                string
			Input, External, Canonical, Sidecar []byte
			Snapshot                            ACLIdentitySnapshot
			RestoredKinds                       []string
		}
	}
	if e := json.NewDecoder(z).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	if len(fixture.Records) != 25 || fixture.SourceSHA256 != "929b16ba8d52527c1bb4812ed7ed25f3e43f315516898d1bd777a10ca690e4c2" {
		t.Fatal("incomplete native identity evidence")
	}
	for name, want := range map[string]string{"acl-identity.c": fixture.HelperSHA256, "acl.c": fixture.ACLHelperSHA256} {
		b, e := os.ReadFile("../../testdata/appledouble/native/" + name)
		if e != nil {
			t.Fatal(e)
		}
		s := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
		if hex.EncodeToString(s[:]) != want {
			t.Fatal("native helper changed", name)
		}
	}
	for _, tc := range fixture.Records {
		t.Run(tc.Name, func(t *testing.T) {
			r, l, e := tc.Snapshot.Resolvers()
			if e != nil {
				t.Fatal(e)
			}
			a, e := ParseACLText(tc.Input, r)
			if e != nil {
				t.Fatal(e)
			}
			b, e := a.MarshalBinary()
			if e != nil || !bytes.Equal(b, tc.External) {
				t.Fatal("captured native principal bytes differ", e)
			}
			text, e := a.FormatText(l)
			if e != nil || !bytes.Equal(text, tc.Canonical) {
				t.Fatalf("captured native text differs: %q / %q: %v", text, tc.Canonical, e)
			}
			f, e := Decode(tc.Sidecar)
			if e != nil {
				t.Fatal(e)
			}
			u, e := f.ACLUpdate(r)
			if e != nil || u.RecordIndex != 1 || u.Invalid || u.ACL == nil {
				t.Fatal(u, e)
			}
			b, e = u.ACL.MarshalBinary()
			if e != nil || !bytes.Equal(b, tc.External) {
				t.Fatal("native restored ACL differs", e)
			}
			if !reflect.DeepEqual(tc.RestoredKinds, []string{"file", "directory"}) {
				t.Fatal("missing native restoration evidence")
			}
			if _, e := r(ACLIdentity{Name: "discarded-source-identity"}); !errors.Is(e, ErrACLIdentityUncaptured) {
				t.Fatal("discarded record was resolved", e)
			}
		})
	}
}

func TestACLIdentityCaptureReplay(t *testing.T) {
	forward, reverse := 0, 0
	uuid := [16]byte{1, 2}
	capture := NewACLIdentityCapture(func(id ACLIdentity) ([16]byte, error) {
		forward++
		if id.Name == "absent" {
			return [16]byte{}, nil
		}
		if id.ID != nil {
			*id.ID = 99
		} // The source cannot mutate caller/capture query keys.
		return uuid, nil
	}, func(id [16]byte) (ACLPrincipal, bool, error) {
		reverse++
		if id == [16]byte{} {
			return ACLPrincipal{Name: "discarded", ID: 99}, false, nil
		}
		return ACLPrincipal{Group: true, Name: "source\xff\x00suffix", ID: 0xffffffff}, true, nil
	})
	id := uint32(0)
	queries := []ACLIdentity{{Name: "alias"}, {Group: true, Name: "alias"}, {ID: &id}, {Group: true, ID: &id}, {Name: "absent"}}
	for _, q := range queries {
		for range 2 {
			if _, e := capture.Resolve(q); e != nil {
				t.Fatal(e)
			}
		}
	}
	for _, u := range [][16]byte{uuid, {}} {
		for range 2 {
			if _, _, e := capture.Lookup(u); e != nil {
				t.Fatal(e)
			}
		}
	}
	if forward != 5 || reverse != 2 || id != 0 {
		t.Fatal(forward, reverse, id)
	}
	snapshot := capture.Snapshot()
	b, e := json.Marshal(snapshot)
	if e != nil {
		t.Fatal(e)
	}
	var transported ACLIdentitySnapshot
	if e := json.Unmarshal(b, &transported); e != nil {
		t.Fatal(e)
	}
	r, l, e := transported.Resolvers()
	if e != nil {
		t.Fatal(e)
	}
	for _, q := range queries {
		want := uuid
		if q.Name == "absent" {
			want = [16]byte{}
		}
		if got, e := r(q); e != nil || got != want {
			t.Fatal(got, e)
		}
	}
	if p, found, e := l(uuid); e != nil || !found || p.Name != "source\xff\x00suffix" || !p.Group || p.ID != 0xffffffff {
		t.Fatal(p, found, e)
	}
	if p, found, e := l([16]byte{}); e != nil || found || p != (ACLPrincipal{}) {
		t.Fatal(p, found, e)
	}
	for _, q := range []ACLIdentity{{Name: "uncaptured"}, {Group: true, Name: "absent"}} {
		if _, e := r(q); !errors.Is(e, ErrACLIdentityUncaptured) {
			t.Fatal(e)
		}
	}
	if _, _, e := l([16]byte{3}); !errors.Is(e, ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
	// Snapshots and callbacks own both name bytes and pointed-to IDs.
	transported.Identities[0].Name[0] = 'X'
	*transported.Identities[2].ID = 99
	transported.Principals[0].Name[0] = 'X'
	if got, e := r(queries[0]); e != nil || got != uuid {
		t.Fatal(got, e)
	}
	if got, e := r(queries[2]); e != nil || got != uuid {
		t.Fatal(got, e)
	}
	if p, _, _ := l(uuid); p.Name != "source\xff\x00suffix" {
		t.Fatal(p)
	}
	snapshot.Identities[0].Name[0] = 'Y'
	*snapshot.Identities[2].ID = 100
	snapshot.Principals[0].Name[0] = 'Y'
	if reflect.DeepEqual(snapshot, capture.Snapshot()) {
		t.Fatal("snapshot aliases recorder")
	}
	if got, e := capture.Resolve(queries[0]); e != nil || got != uuid {
		t.Fatal(got, e)
	}
	if p, _, _ := capture.Lookup(uuid); p.Name != "source\xff\x00suffix" {
		t.Fatal(p)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 32 {
				if _, e := r(queries[0]); e != nil {
					t.Error(e)
				}
				if _, _, e := l(uuid); e != nil {
					t.Error(e)
				}
			}
		})
	}
	wg.Wait()
}

func TestACLIdentitySnapshotValidation(t *testing.T) {
	id := uint32(0)
	valid := ACLIdentityBinding{Name: []byte("source")}
	p := ACLPrincipalBinding{UUID: [16]byte{1}, Found: true, Name: []byte("source")}
	for _, s := range []ACLIdentitySnapshot{
		{}, {Version: 2},
		{Version: 1, Identities: []ACLIdentityBinding{{}}},
		{Version: 1, Identities: []ACLIdentityBinding{{Name: []byte("x"), ID: &id}}},
		{Version: 1, Identities: []ACLIdentityBinding{valid, valid}},
		{Version: 1, Principals: []ACLPrincipalBinding{p, p}},
		{Version: 1, Principals: []ACLPrincipalBinding{{Name: []byte("x")}}},
		{Version: 1, Principals: []ACLPrincipalBinding{{Group: true}}},
		{Version: 1, Principals: []ACLPrincipalBinding{{ID: 1}}},
	} {
		r, l, e := s.Resolvers()
		if r != nil || l != nil || !errors.Is(e, ErrACLIdentitySnapshot) {
			t.Fatal(s, e)
		}
	}
	r, l, e := (ACLIdentitySnapshot{Version: 1}).Resolvers()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := r(ACLIdentity{}); !errors.Is(e, ErrACLIdentitySnapshot) {
		t.Fatal(e)
	}
	if _, e := r(ACLIdentity{ID: &id}); !errors.Is(e, ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
	if _, _, e := l([16]byte{}); !errors.Is(e, ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
	// Forward observations never imply reverse answers, and vice versa.
	r, l, e = (ACLIdentitySnapshot{Version: 1, Identities: []ACLIdentityBinding{valid}, Principals: []ACLPrincipalBinding{p}}).Resolvers()
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e := l([16]byte{}); !errors.Is(e, ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
	if _, e := r(ACLIdentity{Name: "alias-not-recorded"}); !errors.Is(e, ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
}

func TestACLIdentityCaptureErrorsAndSelection(t *testing.T) {
	var nilCapture *ACLIdentityCapture
	for _, c := range []*ACLIdentityCapture{nilCapture, {}, NewACLIdentityCapture(nil, nil)} {
		if _, e := c.Resolve(ACLIdentity{}); !errors.Is(e, ErrACLIdentitySnapshot) {
			t.Fatal(e)
		}
		if _, e := c.Resolve(ACLIdentity{Name: "source"}); !errors.Is(e, ErrACLResolver) {
			t.Fatal(e)
		}
		if _, _, e := c.Lookup([16]byte{}); !errors.Is(e, ErrACLResolver) {
			t.Fatal(e)
		}
		s := c.Snapshot()
		if s.Version != 1 || len(s.Identities) != 0 || len(s.Principals) != 0 {
			t.Fatal(s)
		}
	}
	failure := fmt.Errorf("source offline: %w", ErrACLText)
	fail := true
	fc, rc := 0, 0
	c := NewACLIdentityCapture(func(ACLIdentity) ([16]byte, error) {
		fc++
		if fail {
			return [16]byte{9}, failure
		}
		return [16]byte{1}, nil
	}, func([16]byte) (ACLPrincipal, bool, error) {
		rc++
		if fail {
			return ACLPrincipal{Name: "partial"}, true, failure
		}
		return ACLPrincipal{Name: "source"}, true, nil
	})
	f := &File{Attrs: []Attr{{Name: ACLTextName, Value: []byte("!#acl 1\nuser::discarded::allow:read\n")}, {Name: ACLTextName, Value: []byte("!#acl 1\nuser::selected::allow:read\n")}, {Name: ACLTextName}}}
	u, e := f.ACLUpdate(c.Resolve)
	if !errors.Is(e, failure) || u.Invalid || u.ACL != nil {
		t.Fatal(u, e)
	}
	if p, found, e := c.Lookup([16]byte{1}); !errors.Is(e, failure) || p != (ACLPrincipal{}) || found {
		t.Fatal(p, found, e)
	}
	if s := c.Snapshot(); len(s.Identities) != 0 || len(s.Principals) != 0 {
		t.Fatal("failed lookups captured", s)
	}
	fail = false
	u, e = f.ACLUpdate(c.Resolve)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = u.ACL.FormatText(c.Lookup); e != nil {
		t.Fatal(e)
	}
	s := c.Snapshot()
	if fc != 2 || rc != 2 || len(s.Identities) != 1 || string(s.Identities[0].Name) != "selected" {
		t.Fatal(fc, rc, s)
	}
	r, l, e := s.Resolvers()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParseACLText([]byte("!#acl 1\nuser::uncaptured::allow:read\n"), r); !errors.Is(e, ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
	if _, e = (&ACL{Entries: []ACLEntry{{Principal: [16]byte{2}, Flags: 1}}}).FormatText(l); !errors.Is(e, ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
	// Explicit UUID input and ignored ACE kinds require no identity service.
	empty := NewACLIdentityCapture(nil, nil)
	a, e := ParseACLText([]byte("!#acl 1\nuser:01234567-89AB-CDEF-0123-456789ABCDEF:unused:99:allow:read\n"), empty.Resolve)
	if e != nil || a.Entries[0].Principal[0] != 1 {
		t.Fatal(a, e)
	}
	if _, e = (&ACL{Entries: []ACLEntry{{Flags: 3}}}).FormatText(empty.Lookup); e != nil {
		t.Fatal(e)
	}
	if s := empty.Snapshot(); len(s.Identities) != 0 || len(s.Principals) != 0 {
		t.Fatal(s)
	}
}

func FuzzACLIdentitySnapshot(f *testing.F) {
	f.Add([]byte(`{"Version":1}`))
	f.Add([]byte(`{"Version":1,"Identities":[{"Name":"eA==","UUID":[1]}],"Principals":[{"UUID":[1],"Found":true,"Name":"/w=="}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var s ACLIdentitySnapshot
		if json.Unmarshal(b, &s) != nil {
			return
		}
		r, l, e := s.Resolvers()
		if e != nil {
			if !errors.Is(e, ErrACLIdentitySnapshot) || r != nil || l != nil {
				t.Fatal(e)
			}
			return
		}
		before, e := json.Marshal(s)
		if e != nil {
			t.Fatal(e)
		}
		for _, binding := range s.Identities {
			got, e := r(ACLIdentity{Group: binding.Group, Name: string(binding.Name), ID: binding.ID})
			if e != nil || got != binding.UUID {
				t.Fatal(got, e)
			}
		}
		for _, binding := range s.Principals {
			got, found, e := l(binding.UUID)
			if e != nil || found != binding.Found || got.Group != binding.Group || got.Name != string(binding.Name) || got.ID != binding.ID {
				t.Fatal(got, found, e)
			}
		}
		after, e := json.Marshal(s)
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("snapshot mutated")
		}
		var transported ACLIdentitySnapshot
		if e := json.Unmarshal(after, &transported); e != nil {
			t.Fatal(e)
		}
		if _, _, e := transported.Resolvers(); e != nil {
			t.Fatal(e)
		}
	})
}
