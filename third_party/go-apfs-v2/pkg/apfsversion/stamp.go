package apfsversion

import (
	"errors"
	"fmt"
	"strings"
)

// Stamp is one apfs_modified_by_t identifier string as Apple writes it, such
// as "newfs_apfs (2811.160.7.0.4)" or "apfs_kext (3288.1.3)". Tools other than
// Apple's write free text in the same field; go-apfs writes
// "go-apfs (apfswrite)". Such stamps parse with an empty Version and the
// parenthesised text retained in Detail.
type Stamp struct {
	Tool    string
	Version Version
	Detail  string
}

// ErrInvalidStamp reports text that is not "<tool> (<detail>)".
var ErrInvalidStamp = errors.New("apfsversion: invalid stamp")

// ParseStamp parses an on-disk writer identifier. Trailing NUL padding, as
// read from the 32-byte on-disk field, is ignored.
func ParseStamp(s string) (Stamp, error) {
	s = strings.TrimRight(s, "\x00")
	open := strings.IndexByte(s, '(')
	if open <= 0 || !strings.HasSuffix(s, ")") || s[open-1] != ' ' {
		return Stamp{}, fmt.Errorf("%w: %q", ErrInvalidStamp, s)
	}
	stamp := Stamp{Tool: s[:open-1], Detail: s[open+1 : len(s)-1]}
	if stamp.Tool == "" || strings.ContainsAny(stamp.Tool, "()") || stamp.Detail == "" {
		return Stamp{}, fmt.Errorf("%w: %q", ErrInvalidStamp, s)
	}
	if v, err := Parse(stamp.Detail); err == nil {
		stamp.Version = v
	}
	return stamp, nil
}

// IsApple reports a stamp written by one of Apple's APFS tools, which is the
// only kind that carries a build version.
func (s Stamp) IsApple() bool { return !s.Version.IsZero() }

// String renders the on-disk form.
func (s Stamp) String() string {
	if s.Tool == "" {
		return ""
	}
	return s.Tool + " (" + s.Detail + ")"
}
