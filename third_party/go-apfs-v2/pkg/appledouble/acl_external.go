package appledouble

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrACLBinary identifies an invalid or truncated portable external ACL.
var ErrACLBinary = errors.New("appledouble: invalid external ACL")

// ACLPrincipal supplies source identity details for native-style text formatting.
// ID is the UID or GID. Names are emitted as supplied (up to a C-string NUL).
type ACLPrincipal struct {
	Group bool
	Name  string
	ID    uint32
}

// ACLPrincipalResolver performs a source UUID-to-account lookup. found=false
// uses the native unknown-principal form. A lookup error is returned to the
// caller, never hidden or replaced by a receiving-host account lookup.
type ACLPrincipalResolver func([16]byte) (principal ACLPrincipal, found bool, err error)

// ParseACLBinary imports the portable big-endian acl_copy_ext representation.
// Owner/group header UUIDs and trailing bytes are ignored, as in acl_copy_int.
// Unknown flag/right bits and entry kinds are retained. Unlike the lengthless
// native API, this function checks every read and rejects truncated input.
// This does not import acl_copy_ext_native or APFS on-disk security records.
func ParseACLBinary(b []byte) (*ACL, error) {
	return parseACLBinary(b, binary.BigEndian)
}

func parseACLBinary(b []byte, order binary.ByteOrder) (*ACL, error) {
	if len(b) < 44 || order.Uint32(b) != 0x012cc16d {
		return nil, ErrACLBinary
	}
	count := order.Uint32(b[36:])
	if count > 128 || len(b) < 44+24*int(count) {
		return nil, ErrACLBinary
	}
	a := &ACL{Flags: order.Uint32(b[40:]), Entries: make([]ACLEntry, int(count))}
	for i := range a.Entries {
		off := 44 + 24*i
		copy(a.Entries[i].Principal[:], b[off:off+16])
		a.Entries[i].Flags = order.Uint32(b[off+16:])
		a.Entries[i].Rights = order.Uint32(b[off+20:])
	}
	return a, nil
}

var aclGlobalOrder = []string{"defer_inherit", "no_inherit"}
var aclEntryOrder = []string{"inherited", "file_inherit", "directory_inherit", "limit_inherit", "only_inherit"}
var aclRightsOrder = []string{"read", "write", "execute", "delete", "append", "delete_child", "readattr", "writeattr", "readextattr", "writeextattr", "readsecurity", "writesecurity", "chown", "synchronize"}

// MarshalText formats an ACL using explicit UUIDs and no account lookup.
// Use FormatText to supply source identity details for known principals.
func (a *ACL) MarshalText() ([]byte, error) { return a.FormatText(nil) }

// FormatText reproduces acl_to_text's canonical syntax and token order with
// caller-supplied source identity resolution. Without a matching account,
// native syntax uses user:UUID::: even for an originally group-named entry.
// Only allow/deny entries and known bits appear in text; binary export retains
// other entries/bits. Output ends in newline, without a NUL terminator.
func (a *ACL) FormatText(resolve ACLPrincipalResolver) ([]byte, error) {
	if a == nil || len(a.Entries) > 128 {
		return nil, fmt.Errorf("%w: invalid ACL entry count", ErrACLText)
	}
	b := appendACLNames([]byte("!#acl 1"), a.Flags, ' ', aclGlobalOrder, aclGlobalFlags)
	for _, entry := range a.Entries {
		kind := entry.Flags & 15
		if kind != 1 && kind != 2 {
			continue
		}
		var principal ACLPrincipal
		var found bool
		if resolve != nil {
			var err error
			principal, found, err = resolve(entry.Principal)
			if err != nil {
				return nil, fmt.Errorf("appledouble: resolve ACL text principal: %w", err)
			}
		}
		label := "user"
		if found && principal.Group {
			label = "group"
		}
		p := entry.Principal
		b = fmt.Appendf(b, "\n%s:%X-%X-%X-%X-%X:", label, p[:4], p[4:6], p[6:8], p[8:10], p[10:])
		if found {
			name, _, _ := strings.Cut(principal.Name, "\x00")
			b = append(b, name...)
			b = append(b, ':')
			// Native acl_to_text uses %d for the 32-bit UID/GID argument.
			b = strconv.AppendInt(b, int64(int32(principal.ID)), 10)
		} else {
			b = append(b, ':')
		}
		action := ":allow"
		if kind == 2 {
			action = ":deny"
		}
		b = append(b, action...)
		b = appendACLNames(b, entry.Flags, ',', aclEntryOrder, aclEntryFlags)
		b = appendACLNames(b, entry.Rights, ':', aclRightsOrder, aclRights)
	}
	return append(b, '\n'), nil
}

func appendACLNames(b []byte, bits uint32, separator byte, order []string, names map[string]uint32) []byte {
	for _, name := range order {
		if bits&names[name] != 0 {
			b = append(b, separator)
			b = append(b, name...)
			separator = ','
		}
	}
	return b
}
