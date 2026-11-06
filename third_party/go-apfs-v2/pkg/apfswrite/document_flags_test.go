package apfswrite

import (
	"encoding/binary"
	"testing"
)

func TestImageFlagsDocumentIDs(t *testing.T) {
	root := &builderEntry{bsdFlags: 0x40, oid: 2}
	first := &builderEntry{bsdFlags: 0x40, oid: 16}
	alias := &builderEntry{primary: first, bsdFlags: 0x40}
	plain := &builderEntry{oid: 18}
	second := &builderEntry{bsdFlags: 0x40, oid: 19}
	v := &volBuild{root: root, entries: []*builderEntry{first, alias, plain, second}}
	b := &builder{}
	ctx := volCtx{b, v}
	ctx.prepareDocumentIDs()
	if root.documentID != 3 || first.documentID != 4 || second.documentID != 5 || alias.documentID != 0 || plain.documentID != 0 || v.nextDocID != 6 {
		t.Fatal("document ID allocation", v)
	}
	empty := volCtx{b, &volBuild{}}
	empty.prepareDocumentIDs()
	if empty.nextDocID != 3 {
		t.Fatal(empty.nextDocID)
	}
	for _, stream := range []bool{false, true} {
		e := &builderEntry{name: "tracked", documentID: 99, hasStream: stream}
		data := b.inodeValue(e)
		count := binary.LittleEndian.Uint16(data[92:])
		index := 92 + 4 + int(count-1)*4
		if data[index] != 3 || data[index+1] != 0x22 || binary.LittleEndian.Uint16(data[index+2:]) != 4 || binary.LittleEndian.Uint32(data[len(data)-8:]) != 99 {
			t.Fatal("document xfield")
		}
	}
}
