package appledouble

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// DecodeStream indexes the same macOS profile as Decode without reading values
// into memory. It validates the entire bounded header and every referenced span
// before returning, retaining wire order, duplicate records and aliases. Summary
// lengths do not bound actual reads. Unlike Decode, aliases do not consume a
// retained-copy budget proportional to the source file; their logical lengths
// count against limits.MaxTotalValueBytes instead.
//
// The returned values borrow source; the caller must keep it open and immutable.
// Successful indexing does not prove that later value IO will succeed. This is
// a validated snapshot API, not native sequential unpack/partial-mutation policy.
func DecodeStream(ctx context.Context, source Value, limits StreamLimits) (*StreamFile, error) {
	return decodeStream(ctx, source, limits, false)
}

func decodeStream(ctx context.Context, source Value, limits StreamLimits, filesystem bool) (*StreamFile, error) {
	if err := streamContext(ctx); err != nil {
		return nil, err
	}
	if source == nil {
		return nil, errors.New("appledouble: nil streaming source")
	}
	size, err := streamValueSize(source)
	if err != nil {
		return nil, err
	}
	if size > limits.MaxFileBytes {
		return nil, ErrStreamBudget
	}
	if size < 82 {
		return nil, ErrNotAppleDouble
	}
	raw := make([]byte, min(size, MaxHeader))
	if err := streamRead(ctx, source, raw, 0); err != nil {
		return nil, err
	}
	if !Sniff(raw) || binary.BigEndian.Uint16(raw[24:]) != 2 || binary.BigEndian.Uint32(raw[26:]) != entryFinder {
		return nil, ErrNotAppleDouble
	}
	header := bytes.Clone(raw)
	for _, off := range []int{0, 4, 26, 30, 34, 38, 42, 46} {
		native32(header, off)
	}
	native16(header, 24)
	var total uint64
	span := func(offset, length uint32) (Value, error) {
		if length != 0 && uint64(offset)+uint64(length) > size {
			return nil, fmt.Errorf("appledouble: value (offset %d, length %d) outside the file", offset, length)
		}
		if err := limits.addValue(uint64(length), &total); err != nil {
			return nil, err
		}
		return io.NewSectionReader(source, int64(offset), int64(length)), nil
	}
	f := &StreamFile{}
	if binary.BigEndian.Uint32(raw[34:]) > 32 {
		if len(header) < attrEntriesOff || string(raw[attrHeaderOff:attrHeaderOff+4]) != attrMagic {
			return nil, errors.New("appledouble: missing or truncated ATTR header")
		}
		for _, off := range []int{84, 88, 92, 96, 100} {
			native32(header, off)
		}
		native16(header, 116)
		native16(header, 118)
		numAttrs := int(binary.BigEndian.Uint16(raw[118:]))
		off := attrEntriesOff
		for i := 0; i < numAttrs; i++ {
			if !containsRange(len(header), off, 12) {
				return nil, fmt.Errorf("appledouble: truncated attribute entry %d", i)
			}
			native32(header, off)
			native32(header, off+4)
			native16(header, off+8)
			nameLen := int(header[off+10])
			if nameLen < 2 || nameLen > 128 || nameLen > len(header)-off-11 {
				return nil, fmt.Errorf("appledouble: bad name length in attribute entry %d", i)
			}
			name := header[off+11 : off+11+nameLen]
			if name[nameLen-1] != 0 {
				return nil, fmt.Errorf("appledouble: unterminated name in attribute entry %d", i)
			}
			name = name[:bytes.IndexByte(name, 0)]
			if len(name) == 0 || !utf8.Valid(name) {
				return nil, fmt.Errorf("appledouble: invalid name in attribute entry %d", i)
			}
			length := binary.BigEndian.Uint32(raw[off+4:])
			if err := validateFinderInfo(string(name), uint64(length)); err != nil {
				return nil, err
			}
			offset := binary.BigEndian.Uint32(raw[off:])
			// COPYFILE_PACK leaves empty values at offset zero. Native VFS
			// rejects this carrier as an attribute namespace, including its
			// otherwise valid FinderInfo and resource fork. Snapshot unpacking
			// still accepts it. Native VFS-created empty values have a data offset.
			if filesystem && length == 0 && offset == 0 {
				return nil, ErrNotAppleDouble
			}
			value, err := span(offset, length)
			if err != nil {
				return nil, err
			}
			f.Attrs = append(f.Attrs, StreamAttr{Name: string(name), Value: value})
			off += (11 + nameLen + 3) &^ 3
		}
	}
	finderOff := binary.BigEndian.Uint32(raw[30:])
	if uint64(finderOff)+32 > uint64(len(header)) {
		return nil, errors.New("appledouble: FinderInfo outside the native header buffer")
	}
	copy(f.FinderInfo[:], header[int(finderOff):int(finderOff)+32])
	if binary.BigEndian.Uint32(raw[38:]) == entryResource {
		f.ResourceFork, err = span(binary.BigEndian.Uint32(raw[42:]), binary.BigEndian.Uint32(raw[46:]))
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}
