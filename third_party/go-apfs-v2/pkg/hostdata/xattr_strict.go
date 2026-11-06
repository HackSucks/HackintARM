package hostdata

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	// ErrXattrUnsupported means the host or filesystem cannot perform the
	// requested strict attribute operation. It never means the attribute is absent.
	ErrXattrUnsupported = errors.New("strict extended attributes are unsupported")
	// ErrXattrTooLarge means a value or name list exceeds the caller's limit.
	ErrXattrTooLarge = errors.New("extended attribute exceeds read limit")
	// ErrXattrChanged means an observed value or namespace changed during a
	// multi-call query. Some concurrent changes cannot be detected.
	ErrXattrChanged = errors.New("extended attribute changed while reading")
)

// MaxXattrReadSize bounds the allocation made by ReadXattr and ReadXattrNoFollow.
// Unix size queries and removal do not allocate values. Windows native EA queries
// use fixed scratch space bounded to one maximum EA record (65799 bytes).
const MaxXattrReadSize = 8 << 20

// XattrSize returns the visible attribute's byte size and whether it exists on
// the held file descriptor. Empty values are present. Only the native missing-
// attribute error means absent; permission, I/O and unsupported errors survive.
//
// File may identify a regular file, directory or another OS-supported object.
// It remains caller-owned and is never reopened by name. An already-followed
// symlink descriptor refers to its target; an OS-specific link descriptor is
// passed through without a pathname fallback. The operation holds the descriptor
// against concurrent Close using SyscallConn.Control.
//
// Darwin/Linux use the ordinary visible namespace; Windows uses native NTFS EAs
// through supported x/sys wrappers. Darwin compression-hidden attributes are not
// exposed. Windows names are case-insensitive ASCII (at most 254 bytes), and
// zero-length assignment is native deletion, not a present-empty value. Windows
// operations reopen the held object for synchronous EA access without resolving
// its name; current filesystem permissions still apply. Other hosts return
// ErrXattrUnsupported. This API is independent of best-effort ListXattrs.
func XattrSize(file *os.File, name string) (size int, present bool, err error) {
	err = withXattrFile(file, name, func(fd int) error {
		size, present, err = visibleXattrSize(func(buf []byte) (int, error) { return getVisibleXattrFD(fd, name, buf) })
		return err
	})
	return
}

// ReadXattr reads at most maxBytes from a visible attribute on the held file.
// maxBytes must be between zero and MaxXattrReadSize. Missing values return
// (nil, false, nil); present-empty values return a non-nil empty slice and true.
// All errors return nil/false, never a truncated or best-effort value.
//
// The file stays pinned across sizing and reading. A size change/disappearance
// returns ErrXattrChanged without retry; other errors retain their causes.
// This is not an atomic snapshot: same-size changes cannot be detected. Callers
// requiring stable metadata must exclude concurrent mutation. Darwin visibility
// and descriptor ownership are the same as XattrSize.
func ReadXattr(file *os.File, name string, maxBytes int) (value []byte, present bool, err error) {
	if err = xattrReadLimit(maxBytes); err != nil {
		return
	}
	err = withXattrFile(file, name, func(fd int) error {
		value, present, err = readVisibleXattr(func(buf []byte) (int, error) { return getVisibleXattrFD(fd, name, buf) }, maxBytes)
		return err
	})
	return
}

// RemoveXattr requests removal of one attribute from the held file. It returns true
// only when removal succeeds; absence returns false/nil. Other errors survive.
// It never closes, syncs, replaces or reopens file. Hard links share the update;
// metadata change time may advance. Attribute-specific effects (for example on
// compression or ACL state) belong to the filesystem. No rollback or atomic
// multi-attribute operation is provided. Darwin uses ordinary options, without
// XATTR_SHOWCOMPRESSION; read visibility is not a promise about mutation effects.
func RemoveXattr(file *os.File, name string) (removed bool, err error) {
	err = withXattrFile(file, name, func(fd int) error {
		removed, err = removeVisibleXattr(func() error { return removeVisibleXattrFD(fd, name) })
		return err
	})
	return
}

// XattrSizeNoFollow is XattrSize for a path, operating on the final symlink
// itself rather than its target. Intermediate components can still be symlinks.
// It does not provide root containment or pin a pathname against replacement.
// Use the descriptor API when object identity must remain stable.
func XattrSizeNoFollow(path, name string) (int, bool, error) {
	if err := validXattrName(name); err != nil {
		return 0, false, err
	}
	size, present, err := visibleXattrSize(func(buf []byte) (int, error) { return getVisibleXattrPath(path, name, buf) })
	return size, present, strictXattrError(err)
}

// ReadXattrNoFollow reads a bounded visible attribute without following the final
// symlink. Value, limit and error semantics match ReadXattr. Each native call
// resolves path independently: this API is not safe against pathname replacement
// between sizing and reading. Use ReadXattr on a caller-opened file to pin identity.
func ReadXattrNoFollow(path, name string, maxBytes int) ([]byte, bool, error) {
	if err := validXattrName(name); err != nil {
		return nil, false, err
	}
	if err := xattrReadLimit(maxBytes); err != nil {
		return nil, false, err
	}
	value, present, err := readVisibleXattr(func(buf []byte) (int, error) { return getVisibleXattrPath(path, name, buf) }, maxBytes)
	return value, present, strictXattrError(err)
}

// RemoveXattrNoFollow removes one attribute without following the final
// symlink. Absence is false/nil; other errors survive. Intermediate components can
// be symlinks and path is not pinned. Use RemoveXattr for held-object identity.
// The filesystem controls attribute-specific effects, as with RemoveXattr.
func RemoveXattrNoFollow(path, name string) (bool, error) {
	if err := validXattrName(name); err != nil {
		return false, err
	}
	removed, err := removeVisibleXattr(func() error { return removeVisibleXattrPath(path, name) })
	return removed, strictXattrError(err)
}

func validXattrName(name string) error {
	if name == "" || strings.ContainsRune(name, 0) {
		return fmt.Errorf("extended attribute name: %w", os.ErrInvalid)
	}
	return nil
}

func xattrReadLimit(limit int) error {
	if limit < 0 || limit > MaxXattrReadSize {
		return fmt.Errorf("extended attribute read limit: %w", os.ErrInvalid)
	}
	return nil
}

func withXattrFile(file *os.File, name string, action func(int) error) error {
	if err := validXattrName(name); err != nil {
		return err
	}
	return withXattrDescriptor(file, action)
}

func withXattrDescriptor(file *os.File, action func(int) error) error {
	if file == nil {
		return os.ErrInvalid
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var operationErr error
	if err := conn.Control(func(fd uintptr) { operationErr = action(int(fd)) }); err != nil {
		return err
	}
	return strictXattrError(operationErr)
}

func visibleXattrSize(get func([]byte) (int, error)) (int, bool, error) {
	size, err := get(nil)
	if missingXattr(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if size < 0 {
		return 0, false, ErrXattrChanged
	}
	return size, true, nil
}

func readVisibleXattr(get func([]byte) (int, error), limit int) ([]byte, bool, error) {
	size, present, err := visibleXattrSize(get)
	if err != nil || !present {
		return nil, false, err
	}
	if size > limit {
		return nil, false, ErrXattrTooLarge
	}
	// A zero-length destination asks the kernel for size again. Use one byte for
	// an empty value so the second call really reads and detects observed growth.
	value := make([]byte, max(size, 1))
	n, err := get(value)
	if missingXattr(err) || xattrRangeError(err) {
		return nil, false, errors.Join(ErrXattrChanged, err)
	}
	if err != nil {
		return nil, false, err
	}
	if n != size {
		return nil, false, ErrXattrChanged
	}
	return value[:n], true, nil
}

func removeVisibleXattr(remove func() error) (bool, error) {
	err := remove()
	if missingXattr(err) {
		return false, nil
	}
	return err == nil, err
}
