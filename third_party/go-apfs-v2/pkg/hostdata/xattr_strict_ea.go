package hostdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// NT queries transfer complete EA records. Bound scratch to one maximum record:
// header, 255-byte name, terminator and 65535-byte value.
const strictWindowsEABufferSize = 8 + 255 + 1 + 65535

// parseXattrEA validates one FILE_FULL_EA_INFORMATION record. The returned value
// aliases scratch; callers must consume it before the next query. Name is owned.
func parseXattrEA(record []byte) (string, []byte, error) {
	if len(record) < 9 || binary.LittleEndian.Uint32(record) != 0 {
		return "", nil, ErrXattrListMalformed
	}
	namesize := int(record[5])
	size := int(binary.LittleEndian.Uint16(record[6:]))
	valueAt := 9 + namesize
	if namesize == 0 || valueAt > len(record) || size > len(record)-valueAt || record[valueAt-1] != 0 || bytes.IndexByte(record[8:valueAt-1], 0) >= 0 {
		return "", nil, ErrXattrListMalformed
	}
	return string(record[8 : valueAt-1]), record[valueAt : valueAt+size], nil
}

func readXattrEAs(next func([]byte, bool) (int, error), limit int) ([]string, error) {
	scratch := make([]byte, strictWindowsEABufferSize)
	names := []string{}
	seen := map[string]bool{}
	total := 0
	for {
		n, err := next(scratch, len(names) == 0)
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		if n < 0 || n > len(scratch) {
			return nil, ErrXattrListMalformed
		}
		name, _, err := parseXattrEA(scratch[:n])
		if err != nil {
			return nil, err
		}
		// NT EA names are case insensitive. Fold ASCII for duplicate detection only;
		// preserve other raw OEM bytes and return the original name unchanged.
		key := []byte(name)
		for i, b := range key {
			if b >= 'a' && b <= 'z' {
				key[i] = b - ('a' - 'A')
			}
		}
		if seen[string(key)] {
			return nil, ErrXattrChanged
		}
		if len(name)+1 > limit-total {
			return nil, ErrXattrTooLarge
		}
		seen[string(key)] = true
		total += len(name) + 1
		names = append(names, name)
	}
}
