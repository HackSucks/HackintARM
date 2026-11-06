package appledouble

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestNativeACLUpdate(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/acl-update.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []struct {
			Name, Kind            string
			Records               [][]byte
			Raw, Before, After    []byte
			Accepted, AfterAbsent bool
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Records) != 42 {
		t.Fatal("missing native cases", len(fixture.Records))
	}
	for _, tc := range fixture.Records {
		t.Run(tc.Kind+"/"+tc.Name, func(t *testing.T) {
			if !tc.Accepted {
				t.Fatal("fixture native unpack failed")
			}
			file, err := Decode(tc.Raw)
			if err != nil {
				t.Fatal(err)
			}
			update, err := file.ACLUpdate(nil)
			if err != nil {
				t.Fatal(err)
			}
			index := -1
			for i, v := range tc.Records {
				if len(v) != 0 {
					index = i
				}
			}
			if update.RecordIndex != index {
				t.Fatal("selected record", update.RecordIndex, index)
			}
			invalid := tc.Name == "nul-record" || tc.Name == "invalid" || tc.Name == "allow-then-invalid" || tc.Name == "clear-then-invalid"
			if update.Invalid != invalid {
				t.Fatal("ignored malformed policy", update)
			}
			if update.ACL == nil {
				if tc.AfterAbsent || !bytes.Equal(tc.Before, tc.After) {
					t.Fatal("native changed ACL for no-op")
				}
				return
			}
			if tc.AfterAbsent {
				if len(update.ACL.Entries) != 0 || update.ACL.Flags != 0 {
					t.Fatal("native cleared nonempty ACL", update.ACL)
				}
				return
			}
			b, err := update.ACL.MarshalBinary()
			if err != nil || !bytes.Equal(b, tc.After) {
				t.Fatalf("native replacement differs: %x / %x: %v", b, tc.After, err)
			}
		})
	}
}

func TestACLUpdateSelectionAndErrors(t *testing.T) {
	for _, f := range []*File{nil, {}, {Attrs: []Attr{{Name: ACLTextName}, {Name: "ordinary", Value: []byte("INVALID")}}}} {
		u, err := f.ACLUpdate(nil)
		if err != nil || u.RecordIndex != -1 || u.ACL != nil || u.Invalid {
			t.Fatal(u, err)
		}
	}
	text := []byte("!#acl 1\nuser::source::allow:read\n")
	f := &File{Attrs: []Attr{{Name: ACLTextName, Value: []byte("INVALID")}, {Name: "ordinary", Value: []byte("x")}, {Name: ACLTextName, Value: text}, {Name: ACLTextName}}}
	if u, err := f.ACLUpdate(nil); !errors.Is(err, ErrACLResolver) || u.RecordIndex != 2 || u.Invalid || u.ACL != nil {
		t.Fatal(u, err)
	}
	for _, failure := range []error{errors.New("source offline"), fmt.Errorf("source wrapper: %w", ErrACLText)} {
		u, err := f.ACLUpdate(func(ACLIdentity) ([16]byte, error) { return [16]byte{}, failure })
		if !errors.Is(err, failure) || u.Invalid || u.ACL != nil {
			t.Fatal(u, err)
		}
	}
	calls := 0
	u, err := f.ACLUpdate(func(id ACLIdentity) ([16]byte, error) {
		calls++
		if id.Name != "source" {
			t.Fatal(id)
		}
		return [16]byte{1, 2}, nil
	})
	if err != nil || calls != 1 || u.RecordIndex != 2 || u.Invalid || u.ACL.Entries[0].Principal != [16]byte{1, 2} {
		t.Fatal(u, err, calls)
	}
	f.Attrs[2].Value = []byte("INVALID")
	if u.ACL.Entries[0].Principal != [16]byte{1, 2} {
		t.Fatal("result changed with input")
	}
	// Earlier account-based records are never resolved when a later record wins.
	f.Attrs = []Attr{{Name: ACLTextName, Value: text}, {Name: ACLTextName, Value: []byte("!#acl 1\n")}}
	u, err = f.ACLUpdate(func(ACLIdentity) ([16]byte, error) { t.Fatal("resolved discarded record"); return [16]byte{}, nil })
	if err != nil || u.ACL == nil || len(u.ACL.Entries) != 0 || u.RecordIndex != 1 {
		t.Fatal(u, err)
	}
}
