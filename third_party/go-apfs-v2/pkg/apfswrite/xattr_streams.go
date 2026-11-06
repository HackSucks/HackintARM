// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

// addXattrStreams assigns storage and object IDs for one inode's attributes.
// Root and child inodes share the same allocation and accounting path.
func (b volCtx) addXattrStreams(be *builderEntry, streamed map[string]appledouble.Value, nextOID uint64) uint64 {
	// Each streamed attribute owns an object of its own: a data stream
	// with its own oid, extent and refcount, referenced by the
	// attribute record. It carries no inode and no directory entry —
	// it is not a file, only somewhere for the bytes to live.
	for _, name := range sortedNames(streamed) {
		value := streamed[name]
		stream := &builderEntry{
			name:        be.name + ":" + name,
			oid:         nextOID,
			dataValue:   value,
			valueSize:   uint64(value.Size()),
			hasStream:   true,
			blocks:      divRoundUp(uint64(value.Size()), uint64(b.blocksize)),
			allocedSize: 0,
		}
		stream.allocedSize = stream.blocks * uint64(b.blocksize)
		nextOID++

		if be.streamedXattrs == nil {
			be.streamedXattrs = map[string]*builderEntry{}
		}
		be.streamedXattrs[name] = stream
		b.streamFiles = append(b.streamFiles, stream)
		b.xattrStreams = append(b.xattrStreams, stream)
	}

	return nextOID
}

// attributeRecords emits embedded/streamed values and their physical extents.
func (b volCtx) attributeRecords(e *builderEntry) []fsTreeRecord {
	var recs []fsTreeRecord
	recs = append(recs, b.userXattrRecords(e)...)
	for _, name := range sortedNames(e.streamedXattrs) {
		stream := e.streamedXattrs[name]
		recs = append(recs, b.streamedXattrRecord(e.oid, name, stream))
		// No DSTREAM_ID record here, unlike a file's data stream. That
		// record carries a reference count, and an attribute's stream
		// cannot be cloned, so it has exactly one reference and no count
		// to keep. apfsck reports one as "xattrs can't be cloned".
		if stream.blocks > 0 {
			recs = append(recs, b.fileExtentRecord(stream))
		}
	}
	return recs
}
