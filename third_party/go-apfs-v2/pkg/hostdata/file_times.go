package hostdata

import (
	"errors"
	"os"
	"runtime"
	"time"
)

// FileTimes contains four independently observed inode timestamps. A non-nil
// writer Entry.Times selects every field, including the Unix epoch; no field is
// inferred from another. The Go zero time is a literal year 1 value, not omission.
// This portable value describes foreign metadata, not host write authorization.
// HFS+ stores whole seconds; APFS stores nanoseconds. Writers reject explicit
// values outside their supported range rather than wrapping them.
type FileTimes struct {
	Birth, Modify, Change, Access time.Time
}

// ErrFileTimesUnsupported identifies hosts without a held-file timestamp setter.
var ErrFileTimesUnsupported = errors.New("file timestamps are unsupported on this host")

// SetFileTimes sets modification and access times on an open regular file or
// directory. It retains contents, creation time and file position. Metadata
// change time may advance. Darwin and Linux preserve nanoseconds; Windows
// refuses timestamps that cannot be represented exactly in 100ns FILETIME units.
// The caller owns file and must exclude concurrent metadata changes. Native
// filesystem timestamp precision can differ; callers requiring exact storage
// must read back the result and retain logical values in their metadata carrier.
func SetFileTimes(file *os.File, modify, access time.Time) error {
	if file == nil {
		return os.ErrInvalid
	}
	defer runtime.KeepAlive(file)
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return os.ErrInvalid
	}
	return setFileTimes(file, modify, access)
}
