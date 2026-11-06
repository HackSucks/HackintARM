package appledouble

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// craftPaddedName builds a sidecar with two attributes, declaring the first's name
// length as declared rather than len(name)+1, padding with NULs. The kernel
// advances by the declared length; entrySize uses the trimmed name.
func craftPaddedName(nameA string, declared int, valA []byte, nameB string, valB []byte) []byte {
	entryA := (11 + declared + 3) &^ 3
	entryB := (11 + len(nameB) + 1 + 3) &^ 3
	dataStart := attrEntriesOff + entryA + entryB
	values := len(valA) + len(valB)
	attrEnd := dataStart + values

	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(magic))
	binary.Write(&b, binary.BigEndian, uint32(version))
	b.WriteString(filler)
	binary.Write(&b, binary.BigEndian, uint16(2))
	binary.Write(&b, binary.BigEndian, uint32(entryFinder))
	binary.Write(&b, binary.BigEndian, uint32(finderOffset))
	binary.Write(&b, binary.BigEndian, uint32(attrEnd-finderOffset))
	binary.Write(&b, binary.BigEndian, uint32(entryResource))
	binary.Write(&b, binary.BigEndian, uint32(attrEnd))
	binary.Write(&b, binary.BigEndian, uint32(0))
	b.Write(make([]byte, 32)) // finder info
	b.Write([]byte{0, 0})
	b.WriteString(attrMagic)
	binary.Write(&b, binary.BigEndian, uint32(0))
	binary.Write(&b, binary.BigEndian, uint32(attrEnd))
	binary.Write(&b, binary.BigEndian, uint32(dataStart))
	binary.Write(&b, binary.BigEndian, uint32(values))
	b.Write(make([]byte, 12))
	binary.Write(&b, binary.BigEndian, uint16(0))
	binary.Write(&b, binary.BigEndian, uint16(2)) // two attributes

	// entry A, with an over-declared name length
	binary.Write(&b, binary.BigEndian, uint32(dataStart))
	binary.Write(&b, binary.BigEndian, uint32(len(valA)))
	binary.Write(&b, binary.BigEndian, uint16(0))
	b.WriteByte(byte(declared))
	b.WriteString(nameA)
	for b.Len() < attrEntriesOff+entryA {
		b.WriteByte(0)
	}
	// entry B
	binary.Write(&b, binary.BigEndian, uint32(dataStart+len(valA)))
	binary.Write(&b, binary.BigEndian, uint32(len(valB)))
	binary.Write(&b, binary.BigEndian, uint16(0))
	b.WriteByte(byte(len(nameB) + 1))
	b.WriteString(nameB)
	for b.Len() < dataStart {
		b.WriteByte(0)
	}
	b.Write(valA)
	b.Write(valB)
	return b.Bytes()
}

// TestDecodeAdvancesByDeclaredNameLength covers an attribute whose name is
// stored padded: the record declares a longer name length than the name
// needs, with the remainder NUL.
//
// The kernel steps over whatever nameLen says. Measuring the step from the
// trimmed name instead left the cursor inside the next record, so the
// second attribute was read from the wrong offset. Anything this package
// or the kernel writes stores the name with exactly one NUL, so the two
// agree there; only a padded name tells them apart.
func TestDecodeAdvancesByDeclaredNameLength(t *testing.T) {
	for _, declared := range []int{4, 5, 6, 7, 8, 12} {
		t.Run(fmt.Sprintf("nameLen=%d", declared), func(t *testing.T) {
			raw := craftPaddedName("aaa", declared, []byte("VALUE-A"), "bbb", []byte("VALUE-B"))
			f, err := Decode(raw)
			if err != nil {
				t.Fatalf("declared name length %d was refused: %v", declared, err)
			}
			if len(f.Attrs) != 2 {
				t.Fatalf("read %d attributes, want 2", len(f.Attrs))
			}
			want := []Attr{{Name: "aaa", Value: []byte("VALUE-A")}, {Name: "bbb", Value: []byte("VALUE-B")}}
			for i, w := range want {
				if f.Attrs[i].Name != w.Name {
					t.Errorf("attribute %d name = %q, want %q", i, f.Attrs[i].Name, w.Name)
				}
				if string(f.Attrs[i].Value) != string(w.Value) {
					t.Errorf("attribute %d value = %q, want %q", i, f.Attrs[i].Value, w.Value)
				}
			}
		})
	}
}
