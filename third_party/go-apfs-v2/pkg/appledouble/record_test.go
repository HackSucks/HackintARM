package appledouble

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// These expected maps come from native listxattr/getxattr, never from Decode.
// Unchanged, protected host provenance is retained in the fixture baseline and
// excluded from Expected because it was not supplied by the sidecar.
func TestNativeRecordObservations(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/records.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []struct {
			Name     string
			Raw      []byte
			Accepted bool
			SHA256   string
			Expected map[string][]byte
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Records) != 44 {
		t.Fatalf("native records: %d", len(fixture.Records))
	}
	for _, tc := range fixture.Records {
		t.Run(tc.Name, func(t *testing.T) {
			if fmt.Sprintf("%x", sha256.Sum256(tc.Raw)) != tc.SHA256 {
				t.Fatal("fixture hash mismatch")
			}
			input := bytes.Clone(tc.Raw)
			decoded, err := Decode(input)
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%t, Decode: %v", tc.Accepted, err)
			}
			if !bytes.Equal(input, tc.Raw) {
				t.Fatal("Decode modified input")
			}
			if err != nil {
				return
			}
			equalAttributes(t, decoded.Xattrs(), tc.Expected)
			encoded, err := decoded.Encode()
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			equalAttributes(t, roundtrip.Xattrs(), tc.Expected)
		})
	}
}
func equalAttributes(t *testing.T, got, want map[string][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("attribute count: got %d, want %d", len(got), len(want))
	}
	for name, value := range want {
		actual, ok := got[name]
		if !ok || !bytes.Equal(actual, value) {
			t.Fatalf("attribute %q: got %x (present=%t), want %x", name, actual, ok, value)
		}
	}
}

func TestRecordUnusedOffsetsAndFinderBounds(t *testing.T) {
	raw, err := FromXattrs(map[string][]byte{"empty": nil}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Neither empty payload is read; uint32 offsets must not overflow int on 386.
	binary.BigEndian.PutUint32(raw[120:], ^uint32(0))
	binary.BigEndian.PutUint32(raw[42:], ^uint32(0))
	f, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	equalAttributes(t, f.Xattrs(), map[string][]byte{"empty": nil})
	// FinderInfo is constrained to the native header buffer, not the whole file.
	raw = append(raw, make([]byte, MaxHeader)...)
	binary.BigEndian.PutUint32(raw[30:], MaxHeader-31)
	if _, err := Decode(raw); err == nil {
		t.Fatal("accepted FinderInfo beyond header buffer")
	}
}
