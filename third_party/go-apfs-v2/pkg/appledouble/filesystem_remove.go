package appledouble

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
)

// AttributeFile is an already-authorized, caller-owned AppleDouble file. The
// caller excludes concurrent mutation and handles association, deletion and
// permissions; this interface only permits bounded in-place byte operations.
type AttributeFile interface {
	Value
	io.WriterAt
	Truncate(int64) error
}

// AttributeRemoval records the VFS removal result. Empty requests unlink of the
// associated sidecar by its filesystem owner. No rollback is implied: errors
// after a successful shift/truncate may leave partial modifications.
type AttributeRemoval struct{ Removed, Empty bool }

// FilesystemForkVisible implements the VFS blank-fork tag rule without changing
// the encoded bytes or applying copyfile's separate restoration policy.
func FilesystemForkVisible(ctx context.Context, value Value) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if value == nil || value.Size() == 0 {
		return false, nil
	}
	if value.Size() != 286 {
		return true, nil
	}
	const tag = "This resource fork intentionally left blank   \x00"
	var raw [len(tag)]byte
	if err := streamRead(ctx, value, raw[:], 16); err != nil {
		return false, err
	}
	return string(raw[:]) != tag, nil
}

// DecodeFilesystemStream indexes the qualified VFS attribute-file profile.
// A COPYFILE_PACK snapshot with a zero-offset empty ATTR value remains a valid
// snapshot for DecodeStream, but the native filesystem treats the entire
// carrier as an absent attribute namespace (ErrNotAppleDouble). Association,
// authorization and translating that result for get/list/remove belong to the
// filesystem layer. Native-produced empty values with a data offset are valid.
func DecodeFilesystemStream(ctx context.Context, source Value, limits StreamLimits) (*StreamFile, error) {
	return decodeStream(ctx, source, limits, true)
}

// RemoveFilesystemAttribute applies the byte operations used by XNU's
// default_removexattr_vfs. It preserves allocation slack, record order, unrelated
// bytes and fork offsets; it does not canonicalize through copyfile encoding.
// Association and authorization checks belong to the caller.
func RemoveFilesystemAttribute(ctx context.Context, file AttributeFile, name string) (AttributeRemoval, error) {
	result := AttributeRemoval{}
	decoded, err := DecodeFilesystemStream(ctx, file, DefaultStreamLimits())
	if err != nil {
		return result, err
	}
	fork, err := FilesystemForkVisible(ctx, decoded.ResourceFork)
	if err != nil {
		return result, err
	}
	count := len(decoded.Attrs)
	if fork {
		count++
	}
	if decoded.FinderInfo != [32]byte{} {
		count++
	}
	index := -1
	switch name {
	case FinderInfoName:
		if decoded.FinderInfo == [32]byte{} {
			return result, nil
		}
	case ResourceForkName:
		if !fork {
			return result, nil
		}
	default:
		for i, a := range decoded.Attrs {
			if a.Name == name {
				index = i
				break
			}
		}
		if index < 0 {
			return result, nil
		}
	}
	raw := make([]byte, min(file.Size(), int64(MaxHeader)))
	if err = streamRead(ctx, file, raw, 0); err != nil {
		return result, err
	}
	if err = validateFilesystemLayout(raw, file.Size(), len(decoded.Attrs), fork); err != nil {
		return result, err
	}
	if count == 1 {
		return AttributeRemoval{Removed: true, Empty: true}, nil
	}
	switch name {
	case FinderInfoName:
		offset := int(binary.BigEndian.Uint32(raw[30:34]))
		clear(raw[offset : offset+32])
	case ResourceForkName:
		offset := int64(binary.BigEndian.Uint32(raw[42:46]))
		length := int64(binary.BigEndian.Uint32(raw[46:50]))
		if offset+length == file.Size() {
			if err = ctx.Err(); err != nil {
				return result, err
			}
			if err = file.Truncate(offset); err != nil {
				return result, err
			}
		}
		binary.BigEndian.PutUint32(raw[46:50], 0)
		if len(raw) < 120 {
			raw = append(raw, make([]byte, 120-len(raw))...)
		}
		raw = raw[:120]
	default:
		raw, err = removeFilesystemRecord(ctx, file, raw, index, len(decoded.Attrs))
		if err != nil {
			return result, err
		}
	}
	if err = filesystemWrite(ctx, file, raw, 0); err != nil {
		return result, err
	}
	result.Removed = true
	return result, nil
}

// Snapshot decoding permits aliases and advisory lengths. Mutation additionally
// requires disjoint native header, attribute data and fork storage so a shift or
// truncation cannot invalidate an unrelated value or overwrite its descriptors.
func validateFilesystemLayout(raw []byte, size int64, count int, fork bool) error {
	bad := errors.New("appledouble: overlapping or inconsistent filesystem ranges")
	finderOffset := int64(binary.BigEndian.Uint32(raw[30:34]))
	finderLength := int64(binary.BigEndian.Uint32(raw[34:38]))
	finderEnd := finderOffset + finderLength
	forkOffset := int64(binary.BigEndian.Uint32(raw[42:46]))
	if finderOffset != 50 || finderLength < 32 || finderEnd > size || (fork && forkOffset < finderEnd) {
		return bad
	}
	if finderLength == 32 {
		return nil
	}
	start := int64(binary.BigEndian.Uint32(raw[96:100]))
	end := start + int64(binary.BigEndian.Uint32(raw[100:104]))
	if start > int64(len(raw)) || start < 120 || end > finderEnd {
		return bad
	}
	entry, previous := 120, start
	for i := 0; i < count; i++ {
		entryLength := (11 + int(raw[entry+10]) + 3) &^ 3
		offset := int64(binary.BigEndian.Uint32(raw[entry : entry+4]))
		length := int64(binary.BigEndian.Uint32(raw[entry+4 : entry+8]))
		if int64(entry+entryLength) > start || offset < previous || offset+length > end {
			return bad
		}
		previous = offset + length
		entry += entryLength
	}
	return nil
}

func removeFilesystemRecord(ctx context.Context, file AttributeFile, raw []byte, index, count int) ([]byte, error) {
	start := int64(binary.BigEndian.Uint32(raw[96:100]))
	length := int64(binary.BigEndian.Uint32(raw[100:104]))
	end := start + length
	entry := 120
	for i := 0; i < index; i++ {
		entry += (11 + int(raw[entry+10]) + 3) &^ 3
	}
	entryLength := int64((11 + int(raw[entry+10]) + 3) &^ 3)
	offset := int64(binary.BigEndian.Uint32(raw[entry : entry+4]))
	size := int64(binary.BigEndian.Uint32(raw[entry+4 : entry+8]))
	last := index == count-1
	if !last {
		copy(raw[entry:], raw[int64(entry)+entryLength:start])
	}
	if end > MaxHeader {
		if err := filesystemShift(ctx, file, start, offset-start, entryLength); err != nil {
			return nil, err
		}
		if !last {
			if err := filesystemShift(ctx, file, offset+size, end-offset-size, size+entryLength); err != nil {
				return nil, err
			}
		}
	} else {
		copy(raw[start-entryLength:offset-entryLength], raw[start:offset])
		if !last {
			copy(raw[offset-entryLength:], raw[offset+size:end])
		}
		clear(raw[end-size-entryLength : end])
	}
	binary.BigEndian.PutUint16(raw[118:120], uint16(count-1))
	binary.BigEndian.PutUint32(raw[96:100], uint32(start-entryLength))
	binary.BigEndian.PutUint32(raw[100:104], uint32(length-size))
	entry = 120
	for i := 0; i < count-1; i++ {
		old := int64(binary.BigEndian.Uint32(raw[entry : entry+4]))
		delta := entryLength
		if i >= index {
			delta += size
		}
		binary.BigEndian.PutUint32(raw[entry:entry+4], uint32(old-delta))
		entry += (11 + int(raw[entry+10]) + 3) &^ 3
	}
	if end > MaxHeader {
		return raw[:start-entryLength], nil
	}
	return raw[:end], nil
}

func filesystemShift(ctx context.Context, file AttributeFile, offset, length, delta int64) error {
	var buf [64 << 10]byte
	for length > 0 {
		n := min(int64(len(buf)), length)
		if err := streamRead(ctx, file, buf[:n], offset); err != nil {
			return err
		}
		if err := filesystemWrite(ctx, file, buf[:n], offset-delta); err != nil {
			return err
		}
		offset += n
		length -= n
	}
	return nil
}
func filesystemWrite(ctx context.Context, file io.WriterAt, data []byte, offset int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := file.WriteAt(data, offset)
	if n != len(data) && err == nil {
		err = io.ErrShortWrite
	}
	return err
}
