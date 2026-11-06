package appledouble

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ACLTextName is copyfile's serialized ACL record, not a native ordinary xattr.
const ACLTextName = "com.apple.acl.text"

// ACL holds the information exported by Darwin's acl_copy_ext. Owner/group
// UUIDs are not part of this ACL representation; the external header leaves
// those fields zero, as acl_copy_ext does.
type ACL struct {
	Flags   uint32
	Entries []ACLEntry
}

// ACLEntry retains a principal UUID, ACE kind/inheritance bits and access mask.
// Native text parsing can also produce an inert entry with zero kind/UUID.
type ACLEntry struct {
	Principal [16]byte
	Flags     uint32
	Rights    uint32
}

// ACLIdentity requests a source-system identity lookup. ID is non-nil for a
// numeric UID/GID; otherwise Name is used. Group distinguishes GIDs from UIDs.
type ACLIdentity struct {
	Group bool
	Name  string
	ID    *uint32
}

// ACLResolver resolves source identities without using the receiving host's
// account database. A source lookup that finds no account returns a zero UUID
// and nil error, matching acl_from_text. Lookup failures must return an error.
type ACLResolver func(ACLIdentity) ([16]byte, error)

var (
	ErrACLText     = errors.New("appledouble: invalid ACL text")
	ErrACLResolver = errors.New("appledouble: ACL principal requires a source identity resolver")
)

var aclGlobalFlags = map[string]uint32{"defer_inherit": 1, "no_inherit": 1 << 17}
var aclEntryFlags = map[string]uint32{"inherited": 1 << 4, "file_inherit": 1 << 5, "directory_inherit": 1 << 6, "limit_inherit": 1 << 7, "only_inherit": 1 << 8}
var aclRights = map[string]uint32{"read": 1 << 1, "write": 1 << 2, "execute": 1 << 3, "delete": 1 << 4, "append": 1 << 5, "delete_child": 1 << 6, "readattr": 1 << 7, "writeattr": 1 << 8, "readextattr": 1 << 9, "writeextattr": 1 << 10, "readsecurity": 1 << 11, "writesecurity": 1 << 12, "chown": 1 << 13, "synchronize": 1 << 20}

// ParseACLText interprets the acl_from_text dialect used in AppleDouble ACL
// records. Explicit UUIDs require no resolver and work identically on every OS.
// Name/ID-only entries require a caller-supplied source identity resolver.
// Native quirks (NUL/blank-line termination, ignored fields and invalid UUIDs
// becoming zero) are deliberate; this is not a strict ACL authoring validator.
// Decode retains ACL text verbatim and does not call this policy parser.
func ParseACLText(data []byte, resolve ACLResolver) (*ACL, error) {
	text := string(data)
	if n := strings.IndexByte(text, 0); n >= 0 {
		text = text[:n]
	}
	header, body, _ := strings.Cut(text, "\n")
	fields := strings.SplitN(header, " ", 4)
	if len(fields) < 2 || (fields[0] != "" && !strings.HasPrefix(fields[0], "!#acl")) || aclNumber(fields[1], 0) != 1 {
		return nil, ErrACLText
	}
	acl := &ACL{}
	if len(fields) > 2 {
		var err error
		acl.Flags, err = aclBits(fields[2], aclGlobalFlags)
		if err != nil {
			return nil, err
		}
	}
	for body != "" {
		var line string
		line, body, _ = strings.Cut(body, "\n")
		if line == "" {
			break
		}
		if len(acl.Entries) == 128 {
			return nil, fmt.Errorf("%w: more than 128 entries", ErrACLText)
		}
		entry, err := parseACLEntry(line, resolve)
		if err != nil {
			return nil, err
		}
		acl.Entries = append(acl.Entries, entry)
	}
	return acl, nil
}

func parseACLEntry(line string, resolve ACLResolver) (ACLEntry, error) {
	var entry ACLEntry
	fields := strings.SplitN(line, ":", 7)
	if len(fields) < 5 || fields[0] == "" || (fields[0][0] != 'u' && fields[0][0] != 'g') || fields[4] == "" {
		return entry, ErrACLText
	}
	var principal [16]byte
	switch {
	case fields[1] != "":
		// Darwin ignores uuid_parse's error after zero-initializing the qualifier.
		if len(fields[1]) == 36 && fields[1][8] == '-' && fields[1][13] == '-' && fields[1][18] == '-' && fields[1][23] == '-' {
			raw, err := hex.DecodeString(strings.ReplaceAll(fields[1], "-", ""))
			if err == nil && len(raw) == 16 {
				copy(principal[:], raw)
			}
		}
	case fields[2] != "" || fields[3] != "":
		if fields[2] != "" && fields[0] != "user" && fields[0] != "group" {
			return entry, ErrACLText
		}
		// With an unrecognized u/g-prefixed kind and only a numeric identifier,
		// native parsing consumes the ID without performing a lookup.
		if fields[0] == "user" || fields[0] == "group" {
			identity := ACLIdentity{Group: fields[0] == "group", Name: fields[2]}
			if identity.Name == "" {
				id := uint32(aclNumber(fields[3], 10))
				identity.ID = &id
			}
			if resolve == nil {
				return entry, ErrACLResolver
			}
			var err error
			principal, err = resolve(identity)
			if err != nil {
				return entry, fmt.Errorf("appledouble: resolve ACL principal: %w", err)
			}
		}
	default:
		return entry, ErrACLText
	}
	action, flags, _ := strings.Cut(fields[4], ",")
	if action != "" {
		switch action {
		case "allow":
			entry.Flags = 1
		case "deny":
			entry.Flags = 2
		default:
			return entry, ErrACLText
		}
		extra, err := aclBits(flags, aclEntryFlags)
		if err != nil {
			return entry, err
		}
		entry.Flags |= extra
		entry.Principal = principal
	}
	if len(fields) > 5 {
		var err error
		entry.Rights, err = aclBits(fields[5], aclRights)
		if err != nil {
			return entry, err
		}
	}
	return entry, nil
}

func aclBits(text string, names map[string]uint32) (uint32, error) {
	var bits uint32
	for text != "" {
		var name string
		name, text, _ = strings.Cut(text, ",")
		if name == "" {
			break
		}
		bit, ok := names[name]
		if !ok {
			return 0, fmt.Errorf("%w: unknown token %q", ErrACLText, name)
		}
		bits |= bit
	}
	return bits, nil
}

// Match strtol's numeric prefix, including base-zero header versions. Saturate
// at signed 64-bit bounds (the supported macOS ABI) before UID/GID conversion.
func aclNumber(text string, base int) int64 {
	text = strings.TrimLeft(text, " \t\r\n\v\f")
	if text == "" {
		return 0
	}
	start := 0
	if text[0] == '+' || text[0] == '-' {
		start = 1
	}
	if start == len(text) {
		return 0
	}
	actual := base
	digits := start
	if actual == 0 {
		actual = 10
		if text[start] == '0' {
			actual = 8
			if len(text) > start+2 && (text[start+1] == 'x' || text[start+1] == 'X') && strings.ContainsRune("0123456789abcdefABCDEF", rune(text[start+2])) {
				actual = 16
				digits += 2
			}
		}
	}
	end := digits
	for end < len(text) {
		c := text[end]
		value := strings.IndexByte("0123456789abcdef", c)
		if c >= 'A' && c <= 'F' {
			value = int(c-'A') + 10
		}
		if value < 0 || value >= actual {
			break
		}
		end++
	}
	if end == digits {
		return 0
	}
	// ParseInt base zero rejects legacy octal padding only when it is not valid
	// octal; the prefix scan has already stopped before such a digit.
	value, _ := strconv.ParseInt(text[:end], base, 64)
	return value
}

// MarshalBinary emits the portable big-endian kauth_filesec representation
// produced by acl_copy_ext: 44 header bytes and 24 bytes per entry. It does not
// apply permissions to a host filesystem or change AppleDouble's raw ACL text.
func (a *ACL) MarshalBinary() ([]byte, error) {
	if a == nil || len(a.Entries) > 128 {
		return nil, fmt.Errorf("%w: invalid ACL entry count", ErrACLText)
	}
	b := make([]byte, 44+24*len(a.Entries))
	binary.BigEndian.PutUint32(b, 0x012cc16d)
	binary.BigEndian.PutUint32(b[36:], uint32(len(a.Entries)))
	binary.BigEndian.PutUint32(b[40:], a.Flags)
	for i, e := range a.Entries {
		off := 44 + 24*i
		copy(b[off:], e.Principal[:])
		binary.BigEndian.PutUint32(b[off+16:], e.Flags)
		binary.BigEndian.PutUint32(b[off+20:], e.Rights)
	}
	return b, nil
}
