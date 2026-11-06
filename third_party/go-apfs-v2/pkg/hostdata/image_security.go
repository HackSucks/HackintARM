package hostdata

import (
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// SecurityRecordDisposition distinguishes missing storage from records that
// native statx omits. None of these states describes permission enforcement.
type SecurityRecordDisposition uint8

const (
	SecurityRecordAbsent SecurityRecordDisposition = iota
	SecurityRecordInvalid
	SecurityRecordEmpty
	SecurityRecordACL
)

// ImageSecurity is a source snapshot for CopySecurity. Disposition preserves
// why ACL/UUID properties are absent rather than silently equating malformed
// storage with a missing record. Raw stored bytes remain available through the
// image's Xattrs API; this snapshot represents the native statx property view.
type ImageSecurity struct {
	Source      SecurityCopySource
	Disposition SecurityRecordDisposition
}

// SecurityRecordSizeValid applies XNU's security-xattr extent checks before a
// reader allocates its value: a 44-byte header and up to 128 whole 24-byte ACEs.
func SecurityRecordSizeValid(size uint64) bool {
	return size >= 44 && size <= 44+128*24 && (size-44)%24 == 0
}

// DecodeImageSecurity maps already-read on-disk security bytes to statx source
// properties, in pure Go on every OS. Nil is confirmed absence; non-nil empty
// bytes are an invalid stored value. Read errors must be propagated by the
// caller, never supplied here as absence. An extent rejected before allocation
// can be represented by a non-nil empty slice (SecurityRecordInvalid).
//
// Native XNU ignores invalid size, magic, count and truncated records. Aligned
// surplus ACE storage is accepted but omitted from the returned properties.
// Libc statx does not expose UUID/ACL properties for zero-entry or NOACL records,
// even when they carry UUIDs or flags. Numeric stat properties remain present.
// All output owns its storage; neither native calls nor authorization occur.
func DecodeImageSecurity(uid, gid uint32, mode uint16, record []byte) ImageSecurity {
	m := uint32(mode)
	result := ImageSecurity{Source: SecurityCopySource{UID: uid, GID: gid, Mode: m, Properties: aclmeta.DarwinChmodProperties{UID: &uid, GID: &gid, Mode: &m}}}
	if record == nil {
		return result
	}
	result.Disposition = SecurityRecordInvalid
	if !SecurityRecordSizeValid(uint64(len(record))) {
		return result
	}
	security, err := appledouble.ParseFileSecurity(record)
	if err != nil {
		return result
	}
	if security.ACL == nil || len(security.ACL.Entries) == 0 {
		result.Disposition = SecurityRecordEmpty
		return result
	}
	security.Trailing = nil
	result.Source.Properties.OwnerUUID = &security.OwnerUUID
	result.Source.Properties.GroupUUID = &security.GroupUUID
	result.Source.Properties.RawSecurity = security
	result.Disposition = SecurityRecordACL
	return result
}
