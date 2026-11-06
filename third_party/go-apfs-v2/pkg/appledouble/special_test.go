package appledouble

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestNativeSpecialAttributeObservations(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/special.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Producers []struct {
			Name, Kind, Attribute, SHA256 string
			Value, Raw                    []byte
			SetAccepted                   bool
			Source, Expected              map[string][]byte
		}
		Wire []struct {
			Name, SHA256         string
			Raw                  []byte
			Accepted, PolicyOnly bool
			Expected             map[string][]byte
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Producers) != 30 || len(fixture.Wire) != 25 {
		t.Fatal("required native special-attribute observations missing")
	}
	for _, tc := range fixture.Producers {
		t.Run(tc.Name, func(t *testing.T) {
			// A directory's refusal of forks is filesystem policy, not a wire-format
			// limitation. The codec must remain able to carry such data on every OS.
			from := FromXattrs(map[string][]byte{tc.Attribute: tc.Value})
			_, encodeErr := from.Encode()
			invalidFinder := tc.Attribute == FinderInfoName && len(tc.Value) != 32
			if (encodeErr != nil) != invalidFinder {
				t.Fatalf("input validation: %v", encodeErr)
			}
			if !tc.SetAccepted {
				return
			}
			if fmt.Sprintf("%x", sha256.Sum256(tc.Raw)) != tc.SHA256 {
				t.Fatal("native fixture hash")
			}
			f, err := Decode(tc.Raw)
			if err != nil {
				t.Fatal(err)
			}
			equalAttributes(t, f.Xattrs(), tc.Source)
			encoded, err := f.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, tc.Raw) {
				t.Fatal("native packed bytes changed")
			}
			equalAttributes(t, from.Xattrs(), tc.Expected)
		})
	}
	for _, tc := range fixture.Wire {
		t.Run(tc.Name, func(t *testing.T) {
			if fmt.Sprintf("%x", sha256.Sum256(tc.Raw)) != tc.SHA256 {
				t.Fatal("wire fixture hash")
			}
			f, err := Decode(tc.Raw)
			if (err == nil) != tc.Accepted {
				t.Fatalf("native accepted=%t, Decode: %v", tc.Accepted, err)
			}
			if err != nil {
				return
			}
			encoded, err := f.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, tc.Raw) {
				t.Fatal("wire records changed")
			}
			if tc.PolicyOnly {
				// ACL/quarantine are serialized policy records, not ordinary native xattrs.
				// Preserve them here; native application belongs to the later policy work.
				if len(f.Attrs) != 1 {
					t.Fatal("lost policy record")
				}
				a := f.Attrs[0]
				v, ok := f.Xattrs()[a.Name]
				if !ok || !bytes.Equal(v, a.Value) {
					t.Fatal("discarded serialized policy bytes")
				}
				return
			}
			equalAttributes(t, f.Xattrs(), tc.Expected)
			// Canonicalizing through the logical map must retain the merged fork suffix.
			canonical, err := FromXattrs(f.Xattrs()).Encode()
			if err != nil {
				t.Fatal(err)
			}
			again, err := Decode(canonical)
			if err != nil {
				t.Fatal(err)
			}
			equalAttributes(t, again.Xattrs(), tc.Expected)
		})
	}
}

func TestInvalidFinderInfoRetainedUntilEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			value := bytes.Repeat([]byte{0x41}, n)
			f := FromXattrs(map[string][]byte{FinderInfoName: value})
			if f.Empty() || f.FinderInfo != [32]byte{} {
				t.Fatal("invalid FinderInfo was normalized away")
			}
			if len(f.Attrs) != 1 || f.Attrs[0].Name != FinderInfoName || !bytes.Equal(f.Attrs[0].Value, value) {
				t.Fatal("invalid bytes were not retained")
			}
			if n > 0 {
				value[0] = 0x42
				if f.Attrs[0].Value[0] != 0x41 {
					t.Fatal("builder aliases caller bytes")
				}
			}
			if _, err := f.Encode(); err == nil {
				t.Fatal("encoded invalid FinderInfo")
			}
		})
	}
}

func TestSpecialXattrsDoesNotMutateWireData(t *testing.T) {
	first := []byte("ORIGINAL")
	f := &File{Attrs: []Attr{{Name: ResourceForkName, Value: first}, {Name: ResourceForkName, Value: []byte("NEW")}}, ResourceFork: []byte("X")}
	got := f.Xattrs()
	if string(got[ResourceForkName]) != "XEWGINAL" {
		t.Fatal(got)
	}
	if string(first) != "ORIGINAL" || string(f.ResourceFork) != "X" {
		t.Fatal("overlay mutated wire records")
	}
	got[ResourceForkName][0] = 'Z'
	if string(f.Xattrs()[ResourceForkName]) != "XEWGINAL" {
		t.Fatal("result aliases the file")
	}
}
