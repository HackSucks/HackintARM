package apfs

import (
	"bytes"
	"testing"
)

func TestFileEntryInactiveCompression(t *testing.T) {
	for _, attr := range [][]byte{inlineAttr(3, 65536, []byte{0xff, 'a'}), []byte("stale"), {}} {
		for _, size := range []uint64{0, 12345} {
			fe := &FileEntry{Inode: &Inode{DataStreamSize: size}, dataSize: -1, ExtendedAttributes: []*AttributeValues{}, FileExtents: []*FileExtent{}, CompressedDataAttributeValues: &AttributeValues{ValueData: attr}, FileHandle: bytes.NewReader(attr)}
			got, e := fe.DataSize()
			if e != nil || got != int64(size) {
				t.Fatal(got, e)
			}
			if size == 0 {
				if e = fe.getDataStream(); e != nil {
					t.Fatal(e)
				}
				if got := readAll(t, fe.DataStream, 0); len(got) != 0 {
					t.Fatal("inactive storage became data")
				}
			}
			if fe.CompressedDataHeader != nil {
				t.Fatal("inactive compression parsed")
			}
		}
	}
}
