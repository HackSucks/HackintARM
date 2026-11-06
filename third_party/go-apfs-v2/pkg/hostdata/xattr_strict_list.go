package hostdata

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

// MaxXattrListSize bounds the combined name bytes, including one NUL terminator
// per name. Native Windows queries additionally use one fixed-size EA buffer.
const MaxXattrListSize = 1 << 20

// ErrXattrListMalformed identifies invalid native name framing or repeated names.
// A malformed list is never returned partially or treated as an empty namespace.
var ErrXattrListMalformed = errors.New("malformed extended attribute list")

// ListXattrNames returns the visible names in native order on a caller-held
// descriptor. maxBytes bounds name bytes including their NUL terminators and
// must be between zero and MaxXattrListSize. Empty namespaces return a non-nil
// empty slice. Errors return nil, never a partial list. No sorting, filtering,
// case conversion, value reads through ReadXattr, or pathname fallback occurs.
//
// Darwin/Linux size then read once; an observed size change returns
// ErrXattrChanged. Windows enumerates native EA records on one synchronous handle
// reopened relative to the held object, preserving reparse-point identity. NT
// queries necessarily transfer values into a fixed scratch buffer, but values
// are not retained. Names keep the kernel's byte representation and casing.
//
// The descriptor remains pinned against Close throughout enumeration. The caller
// must exclude concurrent metadata mutation: same-size Unix changes and some
// Windows changes between records cannot be detected. Permission, unsupported
// and I/O errors survive. Visibility is native to the host, not an emulation of
// Darwin metadata on Windows/Linux; foreign metadata still needs a carrier.
func ListXattrNames(file *os.File, maxBytes int) (names []string, err error) {
	if maxBytes < 0 || maxBytes > MaxXattrListSize {
		return nil, fmt.Errorf("extended attribute list limit: %w", os.ErrInvalid)
	}
	err = withXattrDescriptor(file, func(fd int) error {
		names, err = listVisibleXattrFD(fd, maxBytes)
		return err
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

func readXattrNames(list func([]byte) (int, error), limit int) ([]string, error) {
	size, err := list(nil)
	if err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, ErrXattrChanged
	}
	if size > limit {
		return nil, ErrXattrTooLarge
	}
	// A nonempty buffer makes an empty namespace's second call a real read.
	buf := make([]byte, max(size, 1))
	n, err := list(buf)
	if xattrRangeError(err) {
		return nil, errors.Join(ErrXattrChanged, err)
	}
	if err != nil {
		return nil, err
	}
	if n != size {
		return nil, ErrXattrChanged
	}
	return parseXattrNames(buf[:n])
}

func parseXattrNames(buf []byte) ([]string, error) {
	names := []string{}
	seen := map[string]bool{}
	for len(buf) > 0 {
		end := bytes.IndexByte(buf, 0)
		if end <= 0 {
			return nil, ErrXattrListMalformed
		}
		name := string(buf[:end])
		if seen[name] {
			return nil, ErrXattrListMalformed
		}
		seen[name] = true
		names = append(names, name)
		buf = buf[end+1:]
	}
	return names, nil
}
