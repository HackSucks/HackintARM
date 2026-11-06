package apfs

import (
	"fmt"
	"io"
)

// FileExtents retrieves the attribute value data file extents
func (av *AttributeValues) FileExtents(
	reader io.ReaderAt,
	fileSystemBTree *FileSystemBTree,
	xid uint64,
) error {
	if av.ValueDataFileExtents != nil {
		return fmt.Errorf("value data file extents already set")
	}

	if fileSystemBTree == nil {
		return fmt.Errorf("invalid file system B-tree")
	}

	// Get file extents from the B-tree
	extents, err := fileSystemBTree.FileExtents(
		reader,
		av.ValueDataStreamIdentifier,
		xid,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve value data file extents from file system B-tree: %w", err)
	}

	// Store the extents
	av.ValueDataFileExtents = extents

	return nil
}

// DataStream retrieves the attribute value data stream
func (av *AttributeValues) DataStream(
	ioHandle *IOHandle,
	reader io.ReaderAt,
	encryptionContext *EncryptionContext,
	fileSystemBTree *FileSystemBTree,
	xid uint64,
) (*DataStream, error) {

	// Check if this is a data stream reference (flag 0x0001)
	if (av.Flags & ExtendedAttributeFlagDataStream) != 0 {
		// Retrieve file extents if not already loaded
		if av.ValueDataFileExtents == nil {
			err := av.FileExtents(reader, fileSystemBTree, xid)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve attribute value data file extents: %w", err)
			}
		}

		// Create data stream from file extents
		dataStream, err := NewDataStreamFromFileExtents(
			ioHandle,
			encryptionContext,
			av.ValueDataFileExtents,
			av.ValueDataSize,
			false, // Not sparse
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create value data stream from file extents: %w", err)
		}

		// The extent-backed reader reads from the container image
		if dbReader, ok := dataStream.readerAt.(*dataBlockReader); ok {
			dbReader.SetFileHandle(reader)
		}

		return dataStream, nil
	}

	// Check if this is embedded data (flag 0x0002)
	if (av.Flags & ExtendedAttributeFlagEmbedded) != 0 {
		// Create data stream from embedded data
		dataStream, err := NewDataStreamFromData(av.ValueData)
		if err != nil {
			return nil, fmt.Errorf("unable to create value data stream from data: %w", err)
		}

		return dataStream, nil
	}

	return nil, nil
}
