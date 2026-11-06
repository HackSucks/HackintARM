package appledouble

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// Filesystem headers use XNU ATTR_MAX_HDR_SIZE; COPYFILE_PACK permits 18
// additional bytes in its independently defined MaxHeader.
const filesystemMaxHeader = 65536

// EncodeFilesystemTo constructs fresh VFS attribute storage from visible
// metadata. Unlike COPYFILE_PACK encoding, this retains attribute order,
// allocates the native 4 KiB growth increments and installs the blank resource
// fork marker when no fork is supplied. Empty metadata writes nothing.
//
// This is construction, not mutation of existing storage. The caller owns
// association, authorization and publication. Values must remain immutable;
// errors can leave partial output. Resource forks and attribute values stream
// through one 64 KiB buffer. The record table is bounded by MaxHeader.
func (f *StreamFile) EncodeFilesystemTo(ctx context.Context, dst io.Writer, limits StreamLimits) (int64, error) {
	if err := streamContext(ctx); err != nil {
		return 0, err
	}
	if f == nil || dst == nil {
		return 0, errors.New("appledouble: nil filesystem metadata or writer")
	}
	layout, err := f.filesystemHeader(ctx, limits)
	if err != nil || layout == nil {
		return 0, err
	}
	var written int64
	if err = streamWrite(ctx, dst, layout.header, &written); err != nil {
		return written, err
	}
	buf := make([]byte, 64<<10)
	copyValue := func(value Value, size uint64) error {
		for off := uint64(0); off < size; {
			chunk := buf[:min(uint64(len(buf)), size-off)]
			if err := streamRead(ctx, value, chunk, int64(off)); err != nil {
				return err
			}
			if err := streamWrite(ctx, dst, chunk, &written); err != nil {
				return err
			}
			off += uint64(len(chunk))
		}
		return nil
	}
	for _, entry := range layout.entries {
		if err = copyValue(entry.Value, entry.size); err != nil {
			return written, err
		}
	}
	allocated := layout.allocations[len(layout.allocations)-1]
	for uint64(written) < allocated {
		chunk := buf[:min(uint64(len(buf)), allocated-uint64(written))]
		if err = filesystemForkRemnants(ctx, layout.fork, layout.allocations, uint64(written), chunk); err != nil {
			return written, err
		}
		if err = streamWrite(ctx, dst, chunk, &written); err != nil {
			return written, err
		}
	}
	err = copyValue(layout.fork, uint64(layout.fork.Size()))
	return written, errors.Join(err, ctx.Err())
}

// EmptyFilesystemResourceFork is Apple's 286-byte marker for an absent fork in
// filesystem attribute storage. The returned bytes are independently owned.
func EmptyFilesystemResourceFork() []byte {
	b := make([]byte, 286)
	for _, off := range []int{0, 4, 256, 260} {
		binary.BigEndian.PutUint32(b[off:], 256)
	}
	for _, off := range []int{12, 268} {
		binary.BigEndian.PutUint32(b[off:], 30)
	}
	copy(b[16:], "This resource fork intentionally left blank   \x00")
	binary.BigEndian.PutUint16(b[280:], 28)
	binary.BigEndian.PutUint16(b[282:], 30)
	binary.BigEndian.PutUint16(b[284:], math.MaxUint16)
	return b
}

type filesystemEncoding struct {
	header      []byte
	entries     []streamEntry
	fork        Value
	allocations []uint64
}

func (f *StreamFile) filesystemHeader(ctx context.Context, limits StreamLimits) (*filesystemEncoding, error) {
	if len(f.Attrs) > (filesystemMaxHeader-attrEntriesOff)/16 {
		return nil, ErrTooLarge
	}
	entries := make([]streamEntry, 0, len(f.Attrs))
	names := make(map[string]bool, len(f.Attrs))
	headerSize, allocated := uint64(attrEntriesOff), uint64(4096-286)
	var values uint64
	allocations := []uint64{allocated}
	for _, a := range f.Attrs {
		if a.Name == "" || len(a.Name) > 127 || strings.IndexByte(a.Name, 0) >= 0 || !utf8.ValidString(a.Name) || a.Name == FinderInfoName || a.Name == ResourceForkName || names[a.Name] {
			return nil, fmt.Errorf("appledouble: invalid or duplicate filesystem attribute name %q", a.Name)
		}
		names[a.Name] = true
		size, err := streamValueSize(a.Value)
		if err != nil {
			return nil, err
		}
		record := uint64(entrySize(a.Name))
		if size > math.MaxInt32 || record > filesystemMaxHeader-headerSize {
			return nil, ErrTooLarge
		}
		if err = limits.addValue(size, &values); err != nil {
			return nil, err
		}
		headerSize += record
		end := headerSize + values
		if end > math.MaxUint32 {
			return nil, ErrTooLarge
		}
		if end > allocated {
			growth := (end - allocated + 4095) &^ uint64(4095)
			if end <= filesystemMaxHeader && allocated+growth > filesystemMaxHeader {
				growth = filesystemMaxHeader - allocated
			}
			allocated += growth
			allocations = append(allocations, allocated)
			if allocated > math.MaxUint32 {
				return nil, ErrTooLarge
			}
		}
		entries = append(entries, streamEntry{StreamAttr: a, size: size})
	}
	forkSize, err := streamValueSize(f.ResourceFork)
	if err != nil {
		return nil, err
	}
	if forkSize > math.MaxUint32 {
		return nil, ErrTooLarge
	}
	if len(entries) == 0 && forkSize == 0 && f.FinderInfo == [32]byte{} {
		return nil, nil
	}
	total := values
	if err = limits.addValue(forkSize, &total); err != nil {
		return nil, err
	}
	storedFork := forkSize
	if storedFork == 0 {
		storedFork = 286
	}
	if allocated+storedFork > limits.MaxFileBytes {
		return nil, ErrStreamBudget
	}
	fork := f.ResourceFork
	if forkSize == 0 {
		fork = bytes.NewReader(EmptyFilesystemResourceFork())
	}
	header := make([]byte, headerSize)
	put := func(off int, n uint64) { binary.BigEndian.PutUint32(header[off:], uint32(n)) }
	put(0, magic)
	put(4, version)
	copy(header[8:], filler)
	binary.BigEndian.PutUint16(header[24:], 2)
	put(26, entryFinder)
	put(30, finderOffset)
	put(34, allocated-finderOffset)
	put(38, entryResource)
	put(42, allocated)
	put(46, storedFork)
	copy(header[finderOffset:], f.FinderInfo[:])
	copy(header[attrHeaderOff:], attrMagic)
	put(92, allocated)
	put(96, headerSize)
	put(100, values)
	binary.BigEndian.PutUint16(header[118:], uint16(len(entries)))
	off, valueOff := attrEntriesOff, headerSize
	for i, entry := range entries {
		// XNU moves existing values forward, then writes the new record's
		// fields and NUL-terminated name without clearing alignment bytes.
		// Those bytes retain the previous value area's contents.
		used := 11 + len(entry.Name) + 1
		padding := header[off+used : off+entrySize(entry.Name)]
		if err := filesystemForkRemnants(ctx, fork, allocations, uint64(off+used), padding); err != nil {
			return nil, err
		}
		if err := filesystemRecordPadding(ctx, entries[:i], uint64(used), padding); err != nil {
			return nil, err
		}
		put(off, valueOff)
		put(off+4, entry.size)
		header[off+10] = byte(len(entry.Name) + 1)
		copy(header[off+11:], entry.Name)
		off += entrySize(entry.Name)
		valueOff += entry.size
	}
	return &filesystemEncoding{header, entries, fork, allocations}, nil
}

func filesystemRecordPadding(ctx context.Context, previous []streamEntry, offset uint64, dst []byte) error {
	for _, entry := range previous {
		if len(dst) == 0 {
			return nil
		}
		if offset >= entry.size {
			offset -= entry.size
			continue
		}
		count := min(uint64(len(dst)), entry.size-offset)
		if err := streamRead(ctx, entry.Value, dst[:count], int64(offset)); err != nil {
			return err
		}
		dst = dst[count:]
		offset = 0
	}
	return nil
}

// Growing the attribute area moves the fork forward without clearing its old
// bytes. Later attribute writes cover part of those copies; retain their exact
// remainder in allocation slack, including overlapping copies of large forks.
func filesystemForkRemnants(ctx context.Context, fork Value, allocations []uint64, offset uint64, dst []byte) error {
	clear(dst)
	for len(dst) > 0 {
		next := sort.Search(len(allocations), func(i int) bool { return allocations[i] > offset })
		count := uint64(len(dst))
		if next < len(allocations) {
			count = min(count, allocations[next]-offset)
		}
		if next > 0 {
			start := allocations[next-1]
			if offset-start < uint64(fork.Size()) {
				n := min(count, uint64(fork.Size())-(offset-start))
				if err := streamRead(ctx, fork, dst[:n], int64(offset-start)); err != nil {
					return err
				}
			}
		}
		dst = dst[count:]
		offset += count
	}
	return nil
}
