// Package authorization evaluates captured Darwin discretionary filesystem
// authority. It never uses the receiving host's user, groups or permissions.
package authorization

import (
	"encoding/binary"
	"errors"
	"maps"
	"slices"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// ErrAuthority means a required source observation was not captured. It is
// distinct from a native permission denial and must not be treated as a grant.
var ErrAuthority = errors.New("uncaptured filesystem authority")

// Membership distinguishes an observed lookup failure from missing context.
type Membership uint8

const (
	NotMember Membership = iota + 1
	Member
	MembershipFailed
)

// ProcessPolicy records the observed effective VFS owner-permission override.
// Nil is uncaptured. A nonnil zero value records only the ordinary node-permission
// policy; its nil LongPaths field remains an uncaptured path-length policy.
// The observation comes from native process/thread I/O policy, not entitlements
// guessed from an executable or inherited receiving-host process state.
type ProcessPolicy struct {
	IgnoreNodePermissions bool
	// LongPaths records the effective process OR thread support-long-paths policy.
	// Nil is unobserved; pathname operations require an explicit observation.
	LongPaths *bool
}

// Authority supplies effective source credentials, actual UUID membership and
// observed process policy. Groups contain all applicable numeric groups, never
// inferred receiving-host groups. It does not transport sandbox entitlements.
type Authority struct {
	Process        *ProcessPolicy
	UID            uint32
	Groups         []uint32
	UserUUID       *[16]byte
	UserUUIDFailed bool
	Membership     map[[16]byte]Membership
}

// CloneAuthority validates and snapshots credentials before an operation.
func CloneAuthority(value *Authority) (Authority, error) {
	if value == nil || value.UserUUID != nil && value.UserUUIDFailed {
		return Authority{}, ErrAuthority
	}
	for _, m := range value.Membership {
		if m < NotMember || m > MembershipFailed {
			return Authority{}, ErrAuthority
		}
	}
	result := *value
	if value.Process != nil {
		process := *value.Process
		if process.LongPaths != nil {
			observed := *process.LongPaths
			process.LongPaths = &observed
		}
		result.Process = &process
	}
	result.Groups = slices.Clone(value.Groups)
	result.Membership = maps.Clone(value.Membership)
	if value.UserUUID != nil {
		uuid := *value.UserUUID
		result.UserUUID = &uuid
	}
	return result, nil
}

// Darwin ACL rights alias by vnode kind: Search is Execute, AddFile is
// WriteData, and AddSubdirectory is AppendData.
const (
	ReadData        uint32 = 1 << 1
	WriteData       uint32 = 1 << 2
	Search          uint32 = 1 << 3
	Delete          uint32 = 1 << 4
	AddSubdirectory uint32 = 1 << 5
	DeleteChild     uint32 = 1 << 6
	ReadAttributes  uint32 = 1 << 7
	WriteAttributes uint32 = 1 << 8
	ReadXattr       uint32 = 1 << 9
	WriteXattr      uint32 = 1 << 10
	ReadSecurity    uint32 = 1 << 11
	WriteSecurity   uint32 = 1 << 12
	AddFile                = WriteData
)

// ExpandRights applies the XNU generic-right mappings without discarding
// opaque bits; unmapped bits are not interpreted as additional grants.
func ExpandRights(rights uint32) uint32 {
	const read = ReadData | ReadAttributes | ReadXattr | ReadSecurity
	const write = WriteData | AddSubdirectory | Delete | DeleteChild | WriteAttributes | WriteXattr | WriteSecurity
	if rights&(1<<21) != 0 {
		rights |= read | write | Search
	}
	if rights&(1<<22) != 0 {
		rights |= Search
	}
	if rights&(1<<23) != 0 {
		rights |= write
	}
	if rights&(1<<24) != 0 {
		rights |= read
	}
	return rights
}

// Applies evaluates one principal against captured authority. Failed identity
// lookups follow XNU's deny-sensitive behavior; uncaptured lookups return error.
func Applies(a Authority, principal [16]byte, deny bool, stat hostdata.StatCopySource) (bool, error) {
	prefix := [12]byte{0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef}
	if [12]byte(principal[:12]) == prefix {
		switch binary.BigEndian.Uint32(principal[12:]) {
		case 12:
			return true, nil
		case 0xfffffffe:
			return false, nil
		case 10:
			return a.UID == stat.UID, nil
		case 16:
			if a.UserUUIDFailed {
				return deny, nil
			}
			if a.UserUUID == nil {
				return false, ErrAuthority
			}
			return slices.Contains(a.Groups, stat.GID), nil
		}
	}
	if a.UserUUIDFailed {
		return deny, nil
	}
	if a.UserUUID == nil {
		return false, ErrAuthority
	}
	if principal == *a.UserUUID {
		return true, nil
	}
	switch a.Membership[principal] {
	case NotMember:
		return false, nil
	case Member:
		return true, nil
	case MembershipFailed:
		return deny, nil
	default:
		return false, ErrAuthority
	}
}

// EvaluateACL returns rights left for POSIX fallback after ordered ACL
// evaluation. A complete earlier grant terminates evaluation, as in XNU.
// Callers supply already-validated ACL records and captured credentials.
func EvaluateACL(a Authority, entries []appledouble.ACLEntry, requested uint32, stat hostdata.StatCopySource) (uint32, error) {
	residual := requested
	if residual == 0 {
		return 0, nil
	}
	for _, entry := range entries {
		kind := entry.Flags & 15
		if entry.Flags&256 != 0 || kind != 1 && kind != 2 {
			continue
		}
		rights := ExpandRights(entry.Rights)
		relevant := residual
		if kind == 2 {
			relevant = requested
		}
		if relevant&rights == 0 {
			continue
		}
		applies, err := Applies(a, entry.Principal, kind == 2, stat)
		if err != nil {
			return residual, err
		}
		if !applies {
			continue
		}
		if kind == 2 {
			return residual, syscall.EACCES
		}
		residual &^= rights
		if residual == 0 {
			return 0, nil
		}
	}
	return residual, nil
}

// OwnerOverride reports the captured XNU owner-specific permission override.
// Callers requiring pathname fidelity reject missing Process before evaluation.
func OwnerOverride(a Authority, stat hostdata.StatCopySource) bool {
	return a.Process != nil && a.Process.IgnoreNodePermissions && a.UID == stat.UID
}
