package acl

import "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

// DarwinSecurityArgument distinguishes the three extended-chmod security
// arguments without storing native pointers in portable metadata.
type DarwinSecurityArgument uint8

const (
	// DarwinSecurityNone represents KAUTH_FILESEC_NONE (a null pointer).
	DarwinSecurityNone DarwinSecurityArgument = iota
	// DarwinSecurityRecord represents the address of the owned Security bytes.
	DarwinSecurityRecord
	// DarwinSecurityRemove represents _FILESEC_REMOVE_ACL, not a record or null.
	DarwinSecurityRemove
)

// DarwinChmodArguments is the complete argument shape used by extended chmod.
// Omitted UID/GID use Darwin KAUTH_UID_NONE/KAUTH_GID_NONE (-101).
// Omitted mode uses the integer -1, distinct
// from a present mode narrowed to 0xffff. SecurityArgument selects null, record
// or the removal sentinel. Security is non-nil only for a record and owns its
// storage. Adapters must preserve these distinctions through a supported native
// call boundary. Construction neither performs nor authorizes a write.
type DarwinChmodArguments struct {
	UID, GID         uint32
	Mode             int32
	SecurityArgument DarwinSecurityArgument
	Security         []byte
}

// DarwinChmodProperties describes independently present filesec properties.
// Nil pointers mean omitted, while pointers to zero mean explicitly present.
// Mode is narrowed through Darwin's 16-bit mode_t before integer promotion.
//
// RawSecurity corresponds to FILESEC_ACL_RAW, including a present NOACL record.
// Its embedded ownership UUIDs are replaced by OwnerUUID/GroupUUID, or zeroed
// when those properties are omitted, as libSystem does. RemoveACL corresponds
// to the pointer-valued removal property and conflicts with RawSecurity.
//
// Removal with either UUID property present produces a NOACL record carrying
// those UUIDs instead of the removal sentinel. The native operation determines
// its effect; a NOACL record and the removal sentinel remain distinct arguments
// even where both remove the stored ACL. A null argument is different again.
// Inputs are not retained or modified. This representation works on every OS.
type DarwinChmodProperties struct {
	UID, GID, Mode       *uint32
	OwnerUUID, GroupUUID *[16]byte
	RawSecurity          *appledouble.FileSecurity
	RemoveACL            bool
}

// ChmodArguments prepares the same arguments as libSystem's chmodx1 for these
// properties. Invalid or conflicting security returns a zero result and an
// error matching appledouble.ErrFileSecurity. Unknown record bits are retained;
// opaque trailing bytes are rejected. Native property-read errors belong to the
// capture adapter and must not be converted into omitted properties.
func (p DarwinChmodProperties) ChmodArguments() (DarwinChmodArguments, error) {
	if p.RemoveACL && p.RawSecurity != nil {
		return DarwinChmodArguments{}, appledouble.ErrFileSecurity
	}
	r := DarwinChmodArguments{UID: 0xffffff9b, GID: 0xffffff9b, Mode: -1}
	if p.UID != nil {
		r.UID = *p.UID
	}
	if p.GID != nil {
		r.GID = *p.GID
	}
	if p.Mode != nil {
		r.Mode = int32(uint16(*p.Mode))
	}
	if p.RawSecurity == nil && p.OwnerUUID == nil && p.GroupUUID == nil {
		if p.RemoveACL {
			r.SecurityArgument = DarwinSecurityRemove
		}
		return r, nil
	}
	var security appledouble.FileSecurity
	if p.RawSecurity != nil {
		if len(p.RawSecurity.Trailing) != 0 {
			return DarwinChmodArguments{}, appledouble.ErrFileSecurity
		}
		security = *p.RawSecurity
	}
	security.OwnerUUID, security.GroupUUID = [16]byte{}, [16]byte{}
	if p.OwnerUUID != nil {
		security.OwnerUUID = *p.OwnerUUID
	}
	if p.GroupUUID != nil {
		security.GroupUUID = *p.GroupUUID
	}
	b, err := security.MarshalDarwinBinary()
	if err != nil {
		return DarwinChmodArguments{}, err
	}
	r.SecurityArgument, r.Security = DarwinSecurityRecord, b
	return r, nil
}
