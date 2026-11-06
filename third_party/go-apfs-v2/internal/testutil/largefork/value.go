// Package largefork supplies a bounded deterministic acceptance source whose
// logical bytes straddle the AppleDouble 32-bit entry-length boundary.
package largefork

import (
	"io"
	"io/fs"
)

// Size exceeds both a uint32 byte length and a uint32 positional offset.
const Size int64 = (1 << 32) + 17

// Value implements every byte of the source; it is not a size-only placeholder.
// Reads and MaxRead record the actual consumption for qualification evidence.
// A Value belongs to one sequential acceptance operation, not concurrent readers.
type Value struct {
	Reads   int64
	MaxRead int
}

func (*Value) Size() int64 { return Size }
func (v *Value) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= Size {
		return 0, io.EOF
	}
	v.Reads++
	v.MaxRead = max(v.MaxRead, len(p))
	n := int(min(int64(len(p)), Size-off))
	clear(p[:n])
	for _, marker := range []struct {
		offset int64
		data   string
	}{{0, "fork-start"}, {(1 << 32) - 8, "boundary-crossing"}, {Size - 1, "\xff"}} {
		start := max(off, marker.offset)
		end := min(off+int64(n), marker.offset+int64(len(marker.data)))
		if start < end {
			copy(p[start-off:end-off], marker.data[start-marker.offset:end-marker.offset])
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
