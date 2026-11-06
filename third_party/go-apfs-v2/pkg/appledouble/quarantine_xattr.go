package appledouble

// MaxQuarantineXattrSize is the native filesystem import limit, in stored bytes.
// Bytes after the first NUL still count. AppleDouble's serialized q/ envelope
// has different size rules and must be parsed with ParseQuarantine instead.
const MaxQuarantineXattrSize = 382

// ParseQuarantineXattr imports a plain filesystem com.apple.quarantine value
// using the macOS 27 format. It does not read the filesystem or apply policy.
// Use ParseQuarantineXattrWithProfile to select another supported target.
func ParseQuarantineXattr(data []byte) (*Quarantine, error) {
	return ParseQuarantineXattrWithProfile(data, QuarantineMacOS27)
}

// ParseQuarantineXattrWithProfile converts filesystem xattr bytes into a
// quarantine model. Native import checks the entire stored size before adding
// the q/ envelope prefix and interpreting it. Malformed or oversized values and
// unknown profiles return ErrQuarantine. Input storage is never retained.
//
// Reading an absent xattr and handling I/O errors remain caller responsibilities.
// MarshalBinary on the result exports an AppleDouble envelope, not a filesystem
// xattr or a destination-normalized value.
func ParseQuarantineXattrWithProfile(data []byte, profile QuarantineProfile) (*Quarantine, error) {
	if len(data) > MaxQuarantineXattrSize {
		return nil, ErrQuarantine
	}
	envelope := make([]byte, 2+len(data))
	copy(envelope, "q/")
	copy(envelope[2:], data)
	return ParseQuarantineWithProfile(envelope, profile)
}
