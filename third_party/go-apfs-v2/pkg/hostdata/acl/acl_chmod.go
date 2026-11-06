package acl

import "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

// DarwinChmodRequest is the argument data for Darwin's extended chmod operation.
// It is not a packed syscall struct: adapters pass UID, GID, Mode and the address
// of Security as separate arguments through a supported libSystem wrapper.
// Security owns a complete little-endian kauth_filesec, including ownership UUIDs.
// This is the transport used by fchmodx_np, whose authorization differs from
// fsetattrlist even when the requested attributes have the same values.
//
// The request always supplies numeric fields and a security record. It does not
// represent omitted properties, null security pointers or pointer-valued removal
// sentinels. A nil ACL inside Security is the distinct NOACL record encoding.
// Numeric values are preserved literally; 0xffffffff is not the omitted-owner
// sentinel. Use DarwinChmodProperties when properties are independently absent.
// Building a request neither authorizes nor performs a filesystem operation.
type DarwinChmodRequest struct {
	UID, GID uint32
	Mode     uint16
	Security []byte
}

// DarwinChmodRequest prepares the complete captured metadata plus replacement
// security for the same extended chmod call used by copyfile. All platforms use
// the same pure-Go encoding. Unlike the attribute-list API, ownership UUIDs are
// carried in the security blob. Mode narrows to Darwin's 16-bit mode_t, matching
// FILESEC_MODE before promotion to the native integer argument. Zero is retained.
//
// Security must be present and have no opaque trailing bytes. ACL entry limits,
// unknown bits and NOACL flag bytes follow FileSecurity.MarshalDarwinBinary.
// Invalid input returns an error matching appledouble.ErrFileSecurity and a zero
// request. The result shares no storage with the input or another request.
// Adapters must retain object identity and propagate the native operation's real
// errors; substituting attribute-list writes or preflight chmod is not equivalent.
func (m ACLMetadata) DarwinChmodRequest() (DarwinChmodRequest, error) {
	if m.Security == nil || len(m.Security.Trailing) != 0 {
		return DarwinChmodRequest{}, appledouble.ErrFileSecurity
	}
	security, err := m.Security.MarshalDarwinBinary()
	if err != nil {
		return DarwinChmodRequest{}, err
	}
	return DarwinChmodRequest{UID: m.UID, GID: m.GID, Mode: uint16(m.Mode), Security: security}, nil
}
