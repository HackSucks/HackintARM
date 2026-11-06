package decmpfs

import (
	"encoding/binary"
	"testing"
)

func TestValidateLayout(t *testing.T) {
	header := func(method uint32) []byte {
		b := make([]byte, HeaderSize)
		copy(b, HeaderSignature[:])
		binary.LittleEndian.PutUint32(b[4:], method)
		return b
	}
	for _, tc := range []struct {
		name             string
		prefix           []byte
		attr, data, fork uint64
		ok               bool
	}{
		{"fork", header(4), 16, 0, 1, true},
		{"large fork", header(12), 16, 0, 1 << 40, true},
		{"inline", header(3), 17, 0, 0, true},
		{"oversized inline", header(11), 1 << 32, 0, 0, false},
		{"nil", nil, 0, 0, 0, false},
		{"short", []byte{1}, 1, 0, 0, false},
		{"bad magic", make([]byte, 16), 16, 0, 1, false},
		{"missing header", header(3)[:15], 17, 0, 0, false},
		{"long prefix", header(3), 15, 0, 0, false},
		{"unknown method", header(999), 17, 0, 0, false},
		{"data", header(4), 16, 1, 1, false},
		{"missing fork", header(4), 16, 0, 0, false},
		{"fork with inline payload", header(4), 17, 0, 1, false},
		{"independent fork", header(3), 17, 0, 1, true},
		{"no inline payload", header(3), 16, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLayout(tc.prefix, tc.attr, tc.data, tc.fork)
			if (err == nil) != tc.ok {
				t.Fatalf("%v", err)
			}
		})
	}
	// The byte API and a borrowed header agree without reading payload bytes.
	full := append(header(3), 1, 2, 3)
	if err := Validate(full, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLayout(full[:16], uint64(len(full)), 0, 0); err != nil {
		t.Fatal(err)
	}
}
