package apfswrite

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/bsdflags"
	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// APFS extent lengths occupy 56 bits. This writer emits a single physical
// extent per stream, so block-rounded lengths must fit that field.
const maxStreamSize = int64((uint64(1) << 56) - 4096)

func checkedValueSize(v appledouble.Value) (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("apfswrite: nil value source")
	}
	n := v.Size()
	if n < 0 || n > maxStreamSize {
		return 0, fmt.Errorf("apfswrite: value size %d exceeds extent bounds", n)
	}
	return uint64(n), nil
}
func readValueExact(v appledouble.Value, buf []byte, off int64) error {
	n, e := v.ReadAt(buf, off)
	if n != len(buf) {
		return fmt.Errorf("apfswrite: value short read: %w", errors.Join(io.ErrUnexpectedEOF, e))
	}
	if e != nil && e != io.EOF {
		return e
	}
	return nil
}
func entryDataSize(e *Entry) (uint64, error) {
	if e.DataValue == nil {
		return uint64(len(e.Data)), nil
	}
	if e.Data != nil || e.isDirEntry() || e.isSymlinkEntry() {
		return 0, fmt.Errorf("apfswrite: conflicting or non-file DataValue on %q", e.Name)
	}
	return checkedValueSize(e.DataValue)
}

func prepareXattrs(e *Entry) (embedded map[string][]byte, streamed map[string]appledouble.Value, flags uint64, bsd uint32, err error) {
	dataSize, err := entryDataSize(e)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	values := make(map[string]appledouble.Value, len(e.Xattrs)+len(e.XattrValues))
	for name, value := range e.Xattrs {
		values[name] = bytes.NewReader(value)
	}
	for name, value := range e.XattrValues {
		if _, duplicate := values[name]; duplicate {
			return nil, nil, 0, 0, fmt.Errorf("apfswrite: duplicate value source %q", name)
		}
		if _, err = checkedValueSize(value); err != nil {
			return nil, nil, 0, 0, err
		}
		values[name] = value
	}
	flags = inodeNoRsrcFork
	_, compressed := values[decmpfsName]
	bsd, err = bsdflags.Select(e.BSDFlags, compressed, false)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	for _, name := range sortedNames(values) {
		value := values[name]
		size, err := checkedValueSize(value)
		if err != nil {
			return nil, nil, 0, 0, err
		}
		if name == "" {
			return nil, nil, 0, 0, fmt.Errorf("apfswrite: %q has an extended attribute with an empty name", e.Name)
		}
		if strings.ContainsRune(name, 0) {
			return nil, nil, 0, 0, fmt.Errorf("apfswrite: extended attribute name %q on %q contains a NUL", name, e.Name)
		}
		if name == symlinkName {
			return nil, nil, 0, 0, fmt.Errorf("apfswrite: %q sets %s, which the writer emits itself for symbolic links", e.Name, symlinkName)
		}
		switch name {
		case resourceForkName:
			flags = flags&^uint64(inodeNoRsrcFork) | inodeHasRsrcFork
		case decmpfsName:
			if bsd&inoBSDCompressed != 0 {
				header := make([]byte, min(size, uint64(decmpfs.HeaderSize)))
				if err = readValueExact(value, header, 0); err != nil {
					return nil, nil, 0, 0, err
				}
				var forkSize uint64
				if fork, ok := values[resourceForkName]; ok {
					forkSize, err = checkedValueSize(fork)
					if err != nil {
						return nil, nil, 0, 0, err
					}
				}
				if err = decmpfs.ValidateLayout(header, size, dataSize, forkSize); err != nil {
					return nil, nil, 0, 0, fmt.Errorf("apfswrite: %q: %w", e.Name, err)
				}
			}
		case securityName:
			flags |= inodeHasSecurityEA
		case finderInfoName:
			flags |= inodeHasFinderInfo
		}
		if name == resourceForkName || size > maxEmbeddedXattrSize {
			if streamed == nil {
				streamed = map[string]appledouble.Value{}
			}
			streamed[name] = value
		} else {
			if embedded == nil {
				embedded = map[string][]byte{}
			}
			buf := make([]byte, int(size))
			if size > 0 {
				if err = readValueExact(value, buf, 0); err != nil {
					return nil, nil, 0, 0, err
				}
			}
			embedded[name] = buf
		}
	}
	return embedded, streamed, flags, bsd, nil
}

func (e *builderEntry) streamSize() uint64 {
	if e.dataValue != nil {
		return e.valueSize
	}
	return uint64(len(e.data))
}
func (e *builderEntry) copyStream(buf []byte, offset uint64) (int, error) {
	size := e.streamSize()
	if e.dataValue != nil {
		n, err := checkedValueSize(e.dataValue)
		if err != nil {
			return 0, err
		}
		if n != size {
			return 0, fmt.Errorf("apfswrite: value size changed")
		}
		if offset >= size {
			return 0, nil
		}
		count := min(uint64(len(buf)), size-offset)
		if err = readValueExact(e.dataValue, buf[:count], int64(offset)); err != nil {
			return 0, err
		}
		return int(count), nil
	}
	if offset >= size {
		return 0, nil
	}
	return copy(buf, e.data[offset:]), nil
}
