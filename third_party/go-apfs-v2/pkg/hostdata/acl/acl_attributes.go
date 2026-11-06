package acl

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// DarwinACLCommonAttributes is the common-attribute mask for ACLMetadata:
// OWNERID, GRPID, ACCESSMASK, EXTENDED_SECURITY, UUID and GRPUUID. Use only
// these common attributes, with all other masks/options zero. In particular,
// RETURNED_ATTRS and PACK_INVAL_ATTRS change the response layout.
const DarwinACLCommonAttributes uint32 = 0x01c38000

// DarwinACLAttributeBufferSize accommodates this profile's length word, fixed
// fields and largest supported (128-entry) security record. A native read must
// still succeed before its buffer can be decoded; failure never means no ACL.
const DarwinACLAttributeBufferSize = 56 + 44 + 128*24

// ErrDarwinACLAttributes identifies an invalid or incomplete attribute record.
var ErrDarwinACLAttributes = errors.New("invalid Darwin ACL attribute record")

// ParseDarwinACLAttributes decodes a successful getattrlist/fgetattrlist response
// for DarwinACLCommonAttributes, including its length word. The wire order is
// explicitly little-endian on every Go host. Unused caller buffer capacity is
// ignored, but the declared frame and relative security reference must fit.
//
// A zero-length security reference means no ACL. Ownership UUIDs come from the
// separate UUID/GRPUUID fields, not the ignored ownership slots in the ACL blob.
// Numeric UID/GID and raw Darwin mode are retained, including zero. The returned
// security/entries own their storage. This function does no filesystem access,
// permission checks or interpretation of native syscall errors.
func ParseDarwinACLAttributes(b []byte) (ACLMetadata, error) {
	invalid := func() (ACLMetadata, error) { return ACLMetadata{}, ErrDarwinACLAttributes }
	if len(b) < 56 {
		return invalid()
	}
	order := binary.LittleEndian
	size := uint64(order.Uint32(b))
	if size < 56 || size > uint64(len(b)) {
		return invalid()
	}
	offset := int64(int32(order.Uint32(b[16:])))
	length := uint64(order.Uint32(b[20:]))
	if offset < 40 {
		return invalid()
	}
	start := uint64(16 + offset)
	if start > size || length > size-start || length > 44+128*24 {
		return invalid()
	}
	security := &appledouble.FileSecurity{}
	if length != 0 {
		var err error
		security, err = appledouble.ParseDarwinFileSecurity(b[int(start):int(start+length)])
		if err != nil {
			return ACLMetadata{}, fmt.Errorf("%w: %w", ErrDarwinACLAttributes, err)
		}
		if len(security.Trailing) != 0 {
			return invalid()
		}
	}
	copy(security.OwnerUUID[:], b[24:40])
	copy(security.GroupUUID[:], b[40:56])
	return ACLMetadata{Security: security, UID: order.Uint32(b[4:]), GID: order.Uint32(b[8:]), Mode: order.Uint32(b[12:])}, nil
}

// MarshalDarwinACLAttributes builds a setattrlist/fsetattrlist input for
// DarwinACLCommonAttributes. Unlike a read response it has no length word.
// UUID/GRPUUID are encoded separately: EXTENDED_SECURITY ignores ownership in
// its blob. The blob's ownership slots are zeroed without mutating the input.
// A nil ACL emits the NOACL deletion sentinel; a present empty ACL stays present.
//
// Security must be non-nil and cannot contain trailing opaque bytes: the kernel
// requires the referenced security length to equal its declared ACL extent.
// Unknown ACL bits and opaque NOACL flag bytes are preserved. The output owns
// its storage. Encoding does not authorize writes, apply metadata, clear flags
// or claim that foreign hosts implement Darwin permissions.
func (m ACLMetadata) MarshalDarwinACLAttributes() ([]byte, error) {
	if m.Security == nil || len(m.Security.Trailing) != 0 {
		return nil, ErrDarwinACLAttributes
	}
	security := *m.Security
	security.OwnerUUID = [16]byte{}
	security.GroupUUID = [16]byte{}
	blob, err := security.MarshalDarwinBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDarwinACLAttributes, err)
	}
	b := make([]byte, 52+len(blob))
	order := binary.LittleEndian
	order.PutUint32(b, m.UID)
	order.PutUint32(b[4:], m.GID)
	order.PutUint32(b[8:], m.Mode)
	order.PutUint32(b[12:], 40)
	order.PutUint32(b[16:], uint32(len(blob)))
	copy(b[20:36], m.Security.OwnerUUID[:])
	copy(b[36:52], m.Security.GroupUUID[:])
	copy(b[52:], blob)
	return b, nil
}
