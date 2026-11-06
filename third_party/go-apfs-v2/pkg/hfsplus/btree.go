// B-tree reading: header parsing and leaf-chain traversal over a fork.
//
// Adapted from blacktop/go-apfs's hfsplus package (Apache-2.0); the leaf
// walk here follows the FirstLeafNode/FLink sibling chain instead of
// recursing through index nodes, so each node is read exactly once.
package hfsplus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// btree wraps an HFS+ B-tree stored in a special file's fork.
type btree struct {
	fork   *forkReader
	header BTHeaderRec
}

// openBTree reads and validates the header node of a B-tree fork.
func openBTree(fork *forkReader) (*btree, error) {
	buf := make([]byte, 14+106)
	if _, err := fork.ReadAt(buf, 0); err != nil {
		return nil, fmt.Errorf("failed to read B-tree header node: %w", err)
	}

	var desc BTNodeDescriptor
	if err := binary.Read(bytes.NewReader(buf[:14]), binary.BigEndian, &desc); err != nil {
		return nil, fmt.Errorf("failed to parse B-tree node descriptor: %w", err)
	}
	if desc.Kind != BTHeaderNodeKind {
		return nil, fmt.Errorf("invalid B-tree header node kind: %s", desc.Kind)
	}

	bt := &btree{fork: fork}
	if err := binary.Read(bytes.NewReader(buf[14:]), binary.BigEndian, &bt.header); err != nil {
		return nil, fmt.Errorf("failed to parse B-tree header record: %w", err)
	}
	if bt.header.NodeSize < 512 {
		return nil, fmt.Errorf("invalid B-tree node size: %d", bt.header.NodeSize)
	}

	return bt, nil
}

// leafRecord is one record of a leaf node: the raw key (without the
// 2-byte key length) and the raw record data that follows it.
type leafRecord struct {
	key  []byte
	data []byte
}

// walkLeaves visits every record of every leaf node in key order,
// following the FirstLeafNode/FLink sibling chain.
func (bt *btree) walkLeaves(visit func(rec leafRecord) error) error {
	nodeSize := int(bt.header.NodeSize)
	nodeNum := bt.header.FirstLeafNode
	if nodeNum == 0 {
		return nil // empty tree
	}

	visited := make(map[uint32]bool)
	buf := make([]byte, nodeSize)

	for nodeNum != 0 {
		if visited[nodeNum] {
			return fmt.Errorf("B-tree leaf chain loops at node %d", nodeNum)
		}
		visited[nodeNum] = true
		if bt.header.TotalNodes != 0 && nodeNum >= bt.header.TotalNodes {
			return fmt.Errorf("B-tree leaf node %d out of range (total %d)", nodeNum, bt.header.TotalNodes)
		}

		if _, err := bt.fork.ReadAt(buf, int64(nodeNum)*int64(nodeSize)); err != nil {
			return fmt.Errorf("failed to read B-tree node %d: %w", nodeNum, err)
		}

		var desc BTNodeDescriptor
		if err := binary.Read(bytes.NewReader(buf[:14]), binary.BigEndian, &desc); err != nil {
			return fmt.Errorf("failed to parse node %d descriptor: %w", nodeNum, err)
		}
		if desc.Kind != BTLeafNodeKind {
			return fmt.Errorf("node %d in leaf chain has kind %s", nodeNum, desc.Kind)
		}

		numRecords := int(desc.NumRecords)
		if 2*numRecords > nodeSize-14 {
			return fmt.Errorf("node %d record count %d exceeds node size", nodeNum, numRecords)
		}

		// Record offsets are stored as big-endian uint16s at the end of
		// the node, in reverse order. Slot numRecords holds the offset of
		// free space, which bounds the last record.
		offsetTable := nodeSize - 2*(numRecords+1)
		for i := 0; i < numRecords; i++ {
			start := int(binary.BigEndian.Uint16(buf[nodeSize-2*(i+1):]))
			end := int(binary.BigEndian.Uint16(buf[nodeSize-2*(i+2):]))
			if end < start || end > offsetTable {
				// Tolerate a bogus free-space slot on the last record.
				end = offsetTable
			}
			if start < 14 || start+2 > end {
				return fmt.Errorf("node %d record %d has invalid bounds [%d,%d)", nodeNum, i, start, end)
			}

			keyLength := int(binary.BigEndian.Uint16(buf[start:]))
			keyEnd := start + 2 + keyLength
			// Record data is 2-byte aligned after the key.
			dataStart := keyEnd + (keyEnd & 1)
			if keyEnd > end || dataStart > end {
				return fmt.Errorf("node %d record %d key length %d out of bounds", nodeNum, i, keyLength)
			}

			if err := visit(leafRecord{key: buf[start+2 : keyEnd], data: buf[dataStart:end]}); err != nil {
				return err
			}
		}

		nodeNum = desc.FLink
	}

	return nil
}

// forkReader implements io.ReaderAt over a file fork's allocation-block
// extents (fork-logical addressing, clamped to the fork's logical size).
type forkReader struct {
	dev       io.ReaderAt
	blockSize int64
	size      int64 // logical size in bytes
	extents   []ExtentDescriptor
}

// newForkReader returns a reader over a fork of logicalSize bytes stored in
// extents. A fork cannot hold more bytes than its extents cover; checking
// that also keeps a corrupt size of 2^63 or more from turning negative.
func newForkReader(dev io.ReaderAt, blockSize int64, logicalSize uint64, extents []ExtentDescriptor) (*forkReader, error) {
	var blocks uint64
	for _, ext := range extents {
		blocks += uint64(ext.BlockCount)
	}
	if covered := blocks * uint64(blockSize); logicalSize > covered {
		return nil, fmt.Errorf("logical size %d exceeds the %d bytes its extents cover", logicalSize, covered)
	}
	return &forkReader{dev: dev, blockSize: blockSize, size: int64(logicalSize), extents: extents}, nil
}

func (fr *forkReader) Size() int64 { return fr.size }

func (fr *forkReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset %d", off)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= fr.size {
		return 0, io.EOF
	}
	origLen := len(p)
	if int64(len(p)) > fr.size-off {
		p = p[:fr.size-off]
	}

	total := 0
	for len(p) > 0 {
		devOff, runLen, err := fr.mapOffset(off)
		if err != nil {
			return total, err
		}
		n := int64(len(p))
		if n > runLen {
			n = runLen
		}
		read, err := fr.dev.ReadAt(p[:n], devOff)
		total += read
		if err != nil {
			return total, err
		}
		p = p[n:]
		off += n
	}

	if total < origLen {
		return total, io.EOF
	}
	return total, nil
}

// mapOffset translates a fork-logical byte offset to a device offset and
// the number of contiguous bytes available at that position.
func (fr *forkReader) mapOffset(off int64) (devOff, runLen int64, err error) {
	blockOff := off / fr.blockSize
	for _, ext := range fr.extents {
		count := int64(ext.BlockCount)
		if blockOff < count {
			within := off % fr.blockSize
			devOff = (int64(ext.StartBlock)+blockOff)*fr.blockSize + within
			runLen = (count-blockOff)*fr.blockSize - within
			return devOff, runLen, nil
		}
		blockOff -= count
	}
	return 0, 0, fmt.Errorf("offset %d beyond mapped extents", off)
}
