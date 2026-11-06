package apfswrite

import "encoding/binary"

// Tracked documents need a document-ID xfield, even in read-only images. IDs
// are deterministic, volume-local identities for the newly built volume.
func (b volCtx) prepareDocumentIDs() {
	b.nextDocID = minDocID
	entries := append([]*builderEntry{b.root}, b.entries...)
	for _, e := range entries {
		if e == nil || e.primary != nil || e.bsdFlags&0x40 == 0 {
			continue
		}
		e.documentID = b.nextDocID
		b.nextDocID++
	}
}

func appendDocumentID(val []byte, id uint32) []byte {
	if id == 0 {
		return val
	}
	count := binary.LittleEndian.Uint16(val[sizeofInodeVal:])
	used := binary.LittleEndian.Uint16(val[sizeofInodeVal+2:])
	end := sizeofInodeVal + sizeofXfBlob + int(count)*sizeofXField
	out := make([]byte, len(val)+sizeofXField+8)
	copy(out, val[:end])
	binary.LittleEndian.PutUint16(out[sizeofInodeVal:], count+1)
	binary.LittleEndian.PutUint16(out[sizeofInodeVal+2:], used+8)
	out[end] = 3 // INO_EXT_TYPE_DOCUMENT_ID
	out[end+1] = xfDoNotCopy | xfSystemField
	binary.LittleEndian.PutUint16(out[end+2:], 4)
	copy(out[end+sizeofXField:], val[end:])
	binary.LittleEndian.PutUint32(out[len(out)-8:], id)
	return out
}
