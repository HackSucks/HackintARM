package recompression

import (
	"errors"
	"slices"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// ErrAuthority means a required foreign identity observation was
// not supplied. Missing observations are not implicit permission grants or denials.
var ErrAuthority = authorization.ErrAuthority

// Membership preserves the existing recompression identity API.
type Membership = authorization.Membership

const (
	NotMember        = authorization.NotMember
	Member           = authorization.Member
	MembershipFailed = authorization.MembershipFailed
)

// Authority preserves the shared captured-credential API.
type Authority = authorization.Authority

type recompressionAccess struct {
	authority Authority
	acl       []appledouble.ACLEntry
	volume    uint32
	profile   osversion.MacOSProfile
}

func newRecompressionAccess(record metatransport.Record, security *appledouble.FileSecurity, authority *Authority, volume uint32) (*recompressionAccess, error) {
	if record.Darwin.UID == nil || record.Darwin.GID == nil {
		return nil, ErrAuthority
	}
	captured, err := authorization.CloneAuthority(authority)
	if err != nil {
		return nil, err
	}
	result := &recompressionAccess{authority: captured, volume: volume}
	if security != nil {
		if len(security.Trailing) != 0 {
			return nil, appledouble.ErrFileSecurity
		}
		if _, err := security.MarshalBinary(); err != nil {
			return nil, err
		}
		if security.ACL != nil {
			result.acl = slices.Clone(security.ACL.Entries)
		}
	}
	return result, nil
}

// Numeric rights and ordered ACL evaluation follow XNU xnu-11417.140.69:
// bsd/kern/kern_authorization.c kauth_acl_evaluate; bsd/vfs/vfs_subr.c
// vnode_authorize_simple, vnode_authorize_posix and vnode_authattr. Native
// operation corpora independently qualify the actual recompression call sites.
const (
	recompressionReadData        uint32 = 1 << 1
	recompressionWriteData       uint32 = 1 << 2
	recompressionWriteAttributes uint32 = 1 << 8
	recompressionReadXattr       uint32 = 1 << 9
	recompressionWriteXattr      uint32 = 1 << 10
	recompressionWriteSecurity   uint32 = 1 << 12
)

func (a *recompressionAccess) authorize(operation string, stat hostdata.StatCopySource) error {
	var rights uint32
	switch operation {
	case "open-data":
		rights = recompressionReadData | recompressionWriteData
	case "open-fork":
		switch a.profile {
		case osversion.MacOS15:
			rights = recompressionWriteXattr
		case osversion.MacOS26, osversion.MacOS27:
			rights = recompressionReadXattr | recompressionWriteXattr
		default:
			return osversion.ErrMacOSProfile
		}
		// O_CREAT first authorizes creation of the named fork against base data.
		if err := a.rights(recompressionWriteData, stat, false); err != nil {
			return err
		}
	case "attribute":
		rights = recompressionWriteXattr
	case "truncate":
		// A held writable descriptor carries data-write authorization.
		// ftruncate does not reauthorize a later ACL or mode change.
		if a.volume&1 != 0 {
			return syscall.EROFS
		}
		if stat.Flags&0x00040004 != 0 {
			return syscall.EPERM
		}
		return nil
	case "chmod", "flags":
		rights = recompressionWriteSecurity
	case "times":
		if a.authority.UID != 0 && a.authority.UID != stat.UID {
			return syscall.EPERM
		}
		rights = recompressionWriteAttributes
	default:
		return metatransport.ErrInvalid
	}
	err := a.rights(rights, stat, operation == "flags")
	// Explicit futimes and chmod translate authorization EACCES to EPERM.
	if (operation == "times" || operation == "chmod" || operation == "flags") && errors.Is(err, syscall.EACCES) {
		return syscall.EPERM
	}
	return err
}

// chmod additionally checks requested set-ID bits; authorization alone cannot
// infer those bits from the old mode. An unchanged mode requires no ACL check.
func (a *recompressionAccess) chmod(stat hostdata.StatCopySource, mode uint16) error {
	if stat.Mode&07777 == uint32(mode)&07777 {
		return nil
	}
	if a.authority.UID != 0 {
		if mode&02000 != 0 && !slices.Contains(a.authority.Groups, stat.GID) {
			return syscall.EPERM
		}
		if mode&04000 != 0 && a.authority.UID != stat.UID {
			return syscall.EPERM
		}
	}
	return a.authorize("chmod", stat)
}

func (a *recompressionAccess) rights(requested uint32, stat hostdata.StatCopySource, flagsOnly bool) error {
	if a.volume&1 != 0 {
		return syscall.EROFS
	}
	if requested&recompressionWriteXattr != 0 && a.volume&0x01000000 != 0 {
		return syscall.EACCES
	}
	// Activation only changes UF_COMPRESSED. Flag-only updates bypass user flags;
	// system immutable/append flags remain outside this operation's admitted state.
	mask := uint32(0x00020002)
	if requested&^recompressionWriteXattr != 0 {
		mask |= 0x00040004
	}
	if flagsOnly {
		mask = 0x00060000
	}
	if authorization.OwnerOverride(a.authority, stat) {
		mask &= 0xffff0000
	}
	if stat.Flags&mask != 0 {
		return syscall.EPERM
	}
	if a.authority.UID == 0 {
		return nil
	}
	owner := a.authority.UID == stat.UID
	if owner {
		requested &^= recompressionWriteSecurity
	}
	if requested == 0 {
		return nil
	}
	residual, err := authorization.EvaluateACL(a.authority, a.acl, requested, stat)
	if err != nil {
		if errors.Is(err, syscall.EACCES) && authorization.OwnerOverride(a.authority, stat) {
			return nil
		}
		return err
	}
	if owner {
		residual &^= recompressionWriteAttributes
	}
	if residual&recompressionWriteSecurity != 0 {
		return syscall.EACCES
	}
	var needed uint32
	if residual&(recompressionReadData|recompressionReadXattr) != 0 {
		needed |= 4
	}
	if residual&(recompressionWriteData|recompressionWriteAttributes|recompressionWriteXattr) != 0 {
		needed |= 2
	}
	bits := stat.Mode & 7
	if owner {
		bits = stat.Mode >> 6 & 7
	} else if slices.Contains(a.authority.Groups, stat.GID) {
		bits = stat.Mode >> 3 & 7
	}
	if authorization.OwnerOverride(a.authority, stat) {
		return nil
	}
	if bits&needed != needed {
		return syscall.EACCES
	}
	return nil
}
