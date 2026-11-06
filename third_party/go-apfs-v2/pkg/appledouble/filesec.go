package appledouble

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrFileSecurity identifies an invalid extended security record.
var ErrFileSecurity = errors.New("appledouble: invalid file security record")

// FileSecurity represents a kauth_filesec record, including the ownership UUIDs
// deliberately omitted by ACL.MarshalBinary. Numeric UID/GID, mode and BSD flags
// are separate filesystem metadata and are not encoded here. A nil ACL means
// KAUTH_FILESEC_NOACL, distinct from a present zero-entry ACL.
//
// NoACLFlags retains the four uninterpreted flag bytes of a NOACL record. XNU
// does not byte-swap them. It must be zero when ACL is non-nil. Trailing retains
// bytes beyond the declared entries; neither field grants permission or is
// interpreted as additional entries. Inputs and outputs do not share storage.
type FileSecurity struct {
	OwnerUUID  [16]byte
	GroupUUID  [16]byte
	ACL        *ACL
	NoACLFlags [4]byte
	Trailing   []byte
}

// ParseFileSecurity reads the big-endian disk representation of kauth_filesec.
// It is not the serialized com.apple.acl.text AppleDouble record. Raw AppleDouble
// and filesystem xattr APIs continue to retain their original bytes unchanged.
func ParseFileSecurity(b []byte) (*FileSecurity, error) {
	return parseFileSecurity(b, binary.BigEndian)
}

// ParseDarwinFileSecurity reads the little-endian in-memory representation used
// by supported arm64/x86_64 Darwin systems. Byte order is explicit and independent
// of the Go host, so image and carrier processing also work on Linux and Windows.
func ParseDarwinFileSecurity(b []byte) (*FileSecurity, error) {
	return parseFileSecurity(b, binary.LittleEndian)
}

func parseFileSecurity(b []byte, order binary.ByteOrder) (*FileSecurity, error) {
	if len(b) < 44 || order.Uint32(b) != 0x012cc16d {
		return nil, ErrFileSecurity
	}
	s := &FileSecurity{}
	copy(s.OwnerUUID[:], b[4:20])
	copy(s.GroupUUID[:], b[20:36])
	count := order.Uint32(b[36:])
	extent := 44
	if count == 0xffffffff {
		copy(s.NoACLFlags[:], b[40:44])
	} else {
		var err error
		s.ACL, err = parseACLBinary(b, order)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFileSecurity, err)
		}
		extent += 24 * len(s.ACL.Entries)
	}
	s.Trailing = bytes.Clone(b[extent:])
	return s, nil
}

// MarshalBinary emits the big-endian disk representation, preserving ownership,
// NOACL flag bytes and trailing data. It does not interpret filesystem policy.
func (s *FileSecurity) MarshalBinary() ([]byte, error) {
	return s.marshalFileSecurity(binary.BigEndian)
}

// MarshalDarwinBinary emits the little-endian Darwin in-memory representation.
// This does not apply an ACL or authorize any filesystem operation.
func (s *FileSecurity) MarshalDarwinBinary() ([]byte, error) {
	return s.marshalFileSecurity(binary.LittleEndian)
}

func (s *FileSecurity) marshalFileSecurity(order binary.ByteOrder) ([]byte, error) {
	if s == nil || (s.ACL != nil && s.NoACLFlags != [4]byte{}) {
		return nil, ErrFileSecurity
	}
	var b []byte
	if s.ACL == nil {
		b = make([]byte, 44)
		order.PutUint32(b, 0x012cc16d)
		order.PutUint32(b[36:], 0xffffffff)
		copy(b[40:], s.NoACLFlags[:])
	} else {
		var err error
		b, err = s.ACL.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFileSecurity, err)
		}
		fileSecurityEndian(b, binary.BigEndian, order)
	}
	copy(b[4:20], s.OwnerUUID[:])
	copy(b[20:36], s.GroupUUID[:])
	return append(b, s.Trailing...), nil
}

// fileSecurityEndian operates only on already-validated present-ACL records.
func fileSecurityEndian(b []byte, from, to binary.ByteOrder) {
	count := int(from.Uint32(b[36:]))
	for _, offset := range []int{0, 36, 40} {
		to.PutUint32(b[offset:], from.Uint32(b[offset:]))
	}
	for i := 0; i < count; i++ {
		offset := 44 + 24*i + 16
		to.PutUint32(b[offset:], from.Uint32(b[offset:]))
		to.PutUint32(b[offset+4:], from.Uint32(b[offset+4:]))
	}
}

// FileSecurity prepares a selected AppleDouble ACL replacement while retaining
// captured destination owner/group UUIDs. A nil result is a no-op, including an
// ignored malformed record, and needs no destination capture. A real replacement
// requires a destination record, owns a copy of the selected ACL and clears the
// old ACL's unused/trailing data, as a fresh native ACL export does.
//
// Apply only after other metadata. The filesystem adapter must separately retain
// destination numeric ownership/mode, honor restrictive flags and return actual
// write errors. This method does not predict authorization or retry failed writes.
func (update ACLUpdate) FileSecurity(destination *FileSecurity) (*FileSecurity, error) {
	if update.ACL == nil {
		return nil, nil
	}
	if update.Invalid || destination == nil {
		return nil, ErrFileSecurity
	}
	if _, err := update.ACL.MarshalBinary(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFileSecurity, err)
	}
	acl := *update.ACL
	acl.Entries = append([]ACLEntry(nil), update.ACL.Entries...)
	return &FileSecurity{OwnerUUID: destination.OwnerUUID, GroupUUID: destination.GroupUUID, ACL: &acl}, nil
}
