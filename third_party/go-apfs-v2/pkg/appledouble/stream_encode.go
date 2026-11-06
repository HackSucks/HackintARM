package appledouble

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

type streamEntry struct {
	StreamAttr
	size uint64
}

// EncodeTo writes canonical AppleDouble bytes without materializing values.
// It validates names, lengths, header capacity and all budgets before writing.
// Reader/writer failures and cancellation can leave partial output; the returned
// count is the number of bytes accepted by dst. No source is closed or rewound.
// Cancellation is checked between IO calls; it cannot interrupt a blocked
// caller-provided ReaderAt or Writer. Values must stay immutable for this call.
func (f *StreamFile) EncodeTo(ctx context.Context, dst io.Writer, limits StreamLimits) (int64, error) {
	if err := streamContext(ctx); err != nil {
		return 0, err
	}
	if f == nil || dst == nil {
		return 0, errors.New("appledouble: nil streaming file or writer")
	}
	header, entries, forkSize, err := f.streamHeader(limits)
	if err != nil {
		return 0, err
	}
	var written int64
	if err := streamWrite(ctx, dst, header, &written); err != nil {
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
	for _, entry := range entries {
		if err := copyValue(entry.Value, entry.size); err != nil {
			return written, err
		}
	}
	if err := copyValue(f.ResourceFork, forkSize); err != nil {
		return written, err
	}
	return written, nil
}

func (f *StreamFile) streamHeader(limits StreamLimits) ([]byte, []streamEntry, uint64, error) {
	// Every record needs at least 16 bytes. Reject excessive caller slices
	// before allocating a second entry array.
	if len(f.Attrs) > (MaxHeader-attrEntriesOff)/16 {
		return nil, nil, 0, ErrTooLarge
	}
	entries := make([]streamEntry, 0, len(f.Attrs))
	headerSize := attrEntriesOff
	var values uint64
	for _, a := range f.Attrs {
		if a.Name == "" || len(a.Name) > 127 || strings.IndexByte(a.Name, 0) >= 0 || !utf8.ValidString(a.Name) {
			return nil, nil, 0, fmt.Errorf("appledouble: invalid attribute name %q", a.Name)
		}
		size, err := streamValueSize(a.Value)
		if err != nil {
			return nil, nil, 0, err
		}
		if err := validateFinderInfo(a.Name, size); err != nil {
			return nil, nil, 0, err
		}
		if entrySize(a.Name) > MaxHeader-headerSize || size > math.MaxUint32 || values > math.MaxUint32-size {
			return nil, nil, 0, ErrTooLarge
		}
		if err := limits.addValue(size, &values); err != nil {
			return nil, nil, 0, err
		}
		headerSize += entrySize(a.Name)
		entries = append(entries, streamEntry{StreamAttr: a, size: size})
	}
	forkSize, err := streamValueSize(f.ResourceFork)
	if err != nil {
		return nil, nil, 0, err
	}
	if values > math.MaxUint32-uint64(headerSize) || forkSize > math.MaxUint32 {
		return nil, nil, 0, ErrTooLarge
	}
	totalValues := values
	if err := limits.addValue(forkSize, &totalValues); err != nil {
		return nil, nil, 0, err
	}
	attrEnd := uint64(headerSize) + values
	if attrEnd+forkSize > limits.MaxFileBytes {
		return nil, nil, 0, ErrStreamBudget
	}
	slices.SortStableFunc(entries, func(a, b streamEntry) int { return strings.Compare(a.Name, b.Name) })
	header := make([]byte, headerSize)
	put32 := func(off int, value uint64) { binary.BigEndian.PutUint32(header[off:], uint32(value)) }
	put32(0, magic)
	put32(4, version)
	copy(header[8:], filler)
	binary.BigEndian.PutUint16(header[24:], 2)
	put32(26, entryFinder)
	put32(30, finderOffset)
	put32(34, attrEnd-finderOffset)
	put32(38, entryResource)
	put32(42, attrEnd)
	put32(46, forkSize)
	copy(header[finderOffset:], f.FinderInfo[:])
	copy(header[attrHeaderOff:], attrMagic)
	put32(92, attrEnd)
	put32(96, uint64(headerSize))
	put32(100, values)
	binary.BigEndian.PutUint16(header[118:], uint16(len(entries)))
	off, valueOff := attrEntriesOff, uint64(headerSize)
	for _, entry := range entries {
		if entry.size != 0 {
			put32(off, valueOff)
		}
		put32(off+4, entry.size)
		header[off+10] = byte(len(entry.Name) + 1)
		copy(header[off+11:], entry.Name)
		off += entrySize(entry.Name)
		valueOff += entry.size
	}
	return header, entries, forkSize, nil
}
