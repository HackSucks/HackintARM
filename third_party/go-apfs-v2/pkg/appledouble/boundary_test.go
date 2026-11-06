package appledouble

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestCodecNamesAndLimits(t *testing.T) {
	if owner, ok := OwnerName("dir/plain"); ok || owner != "" {
		t.Fatal(owner, ok)
	}
	for _, name := range []string{"", "a\x00b", strings.Repeat("n", 128)} {
		if _, err := (&File{Attrs: []Attr{{Name: name}}}).Encode(); err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
	// Both values and the resource fork live beyond the bounded entry table.
	f := &File{Attrs: []Attr{{Name: "x", Value: make([]byte, MaxHeader-136)}}, ResourceFork: bytes.Repeat([]byte{42}, MaxHeader*2)}
	raw, err := f.Encode()
	if err != nil || len(raw) != MaxHeader*3 {
		t.Fatal(len(raw), err)
	}
	decoded, err := Decode(raw)
	if err != nil || !bytes.Equal(decoded.ResourceFork, f.ResourceFork) || !bytes.Equal(decoded.Attrs[0].Value, f.Attrs[0].Value) {
		t.Fatal("boundary round trip", err)
	}
	f.Attrs[0].Value = append(f.Attrs[0].Value, 0)
	if _, err := f.Encode(); err != nil {
		t.Fatal(err)
	}
}

func TestCodecMalformedBoundaries(t *testing.T) {
	valid, err := FromXattrs(map[string][]byte{"x": []byte("value")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"truncated-entry-table", func(b []byte) []byte { return b[:26] }},
		{"entry-offset", func(b []byte) []byte { binary.BigEndian.PutUint32(b[30:], ^uint32(0)); return b }},
		{"truncated-attribute-record", func(b []byte) []byte { binary.BigEndian.PutUint16(b[118:], 20); return b }},
		{"empty-declared-name", func(b []byte) []byte { b[130] = 0; return b }},
		{"truncated-name", func(b []byte) []byte { b[130] = 255; return b }},
		{"value-offset", func(b []byte) []byte { binary.BigEndian.PutUint32(b[120:], ^uint32(0)); return b }},
		{"value-length", func(b []byte) []byte { binary.BigEndian.PutUint32(b[124:], ^uint32(0)); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.change(bytes.Clone(valid))); err == nil {
				t.Fatal("accepted malformed boundary")
			}
		})
	}
}

func TestCodecWithoutAttributesSection(t *testing.T) {
	raw, err := (&File{ResourceFork: []byte("fork")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, length := range []uint32{0, 31, 32} {
		b := bytes.Clone(raw)
		binary.BigEndian.PutUint32(b[34:], length)
		copy(b[84:], "NONE")
		f, err := Decode(b)
		if err != nil || string(f.ResourceFork) != "fork" || len(f.Attrs) != 0 {
			t.Fatal(f, err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	raw, err := FromXattrs(map[string][]byte{"com.example.empty": {}, "com.example.value": []byte("value"), ResourceForkName: []byte("fork")}).Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("not AppleDouble"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		decoded, err := Decode(raw)
		if err != nil {
			return
		}
		copied := len(decoded.ResourceFork)
		for _, a := range decoded.Attrs {
			copied += len(a.Value)
		}
		if copied > len(raw) {
			t.Fatal("decode amplified retained value bytes")
		}
		encoded, err := decoded.Encode()
		if err == nil {
			if _, err := Decode(encoded); err != nil {
				t.Fatal("encoder produced undecodable data", err)
			}
		}
	})
}
