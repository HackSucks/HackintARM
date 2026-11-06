package authorization

import (
	"context"
	"errors"
	"slices"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// SecurityState records observation of the source extended-security attribute,
// including observed absence. Receiving-host xattr capture is not this evidence.
type SecurityState uint8

const (
	SecurityUncaptured SecurityState = iota
	SecurityAbsent
	SecurityPresent
)

// Mount identifies the logical filesystem on which an operation takes place.
// Identity is a captured mount identity, not a pathname or receiving-host device.
// A path can cross mounts; each Node carries the mount observed for that node.
type Mount struct {
	Identity   string
	Filesystem string
	Flags      uint32
	// CaseSensitive is observed volume name-comparison policy. Nil is unknown.
	// Already-resolved permission checks do not require it; pathname lookup does.
	CaseSensitive *bool
}

// Node supplies an observed vnode's attributes. Observed means the UID, GID,
// complete mode and flags were captured together; zero is a valid value, never a
// substitute for missing metadata. SecurityPresent requires Security; Absent
// requires nil. Identity is the captured file identity within Mount.
type Node struct {
	Stat          hostdata.StatCopySource
	Observed      bool
	SecurityState SecurityState
	Security      *appledouble.FileSecurity
	Mount         *Mount
	Identity      uint64
}

// Evaluator checks captured discretionary permissions after pathname resolution.
// It neither performs native syscalls nor substitutes for sandbox/MAC checks or
// filesystem-specific existence/type restrictions. Call Search for each actually
// traversed parent before checking the requested namespace operation.
type Evaluator struct {
	authority Authority
	profile   osversion.MacOSProfile
}

// New snapshots explicit credentials and selects a qualified macOS profile.
// A nonnil Groups slice declares that the numeric group list is complete.
func New(target osversion.Version, authority *Authority) (*Evaluator, error) {
	profile, err := osversion.ProfileForMacOS(target)
	if err != nil {
		return nil, err
	}
	captured, err := CloneAuthority(authority)
	if err != nil {
		return nil, err
	}
	if captured.Groups == nil || captured.Process == nil {
		return nil, ErrAuthority
	}
	return &Evaluator{authority: captured, profile: profile}, nil
}

func validateNode(ctx context.Context, n Node) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !n.Observed || n.Mount == nil || n.Mount.Identity == "" || n.Mount.Filesystem == "" {
		return ErrAuthority
	}
	if n.SecurityState != SecurityAbsent && n.SecurityState != SecurityPresent || n.SecurityState == SecurityAbsent && n.Security != nil || n.SecurityState == SecurityPresent && n.Security == nil {
		return ErrAuthority
	}
	if n.Security != nil {
		if len(n.Security.Trailing) != 0 {
			return appledouble.ErrFileSecurity
		}
		if _, err := n.Security.MarshalBinary(); err != nil {
			return err
		}
	}
	return nil
}
func entries(n Node) []appledouble.ACLEntry {
	if n.Security != nil && n.Security.ACL != nil {
		return n.Security.ACL.Entries
	}
	return nil
}

func (e *Evaluator) posix(n Node, bits uint32) error {
	if e.authority.UID == 0 || OwnerOverride(e.authority, n.Stat) {
		return nil
	}
	available := n.Stat.Mode & 7
	if e.authority.UID == n.Stat.UID {
		available = n.Stat.Mode >> 6 & 7
	} else if slices.Contains(e.authority.Groups, n.Stat.GID) {
		available = n.Stat.Mode >> 3 & 7
	}
	if available&bits != bits {
		return syscall.EACCES
	}
	return nil
}
func (e *Evaluator) simple(n Node, rights uint32, bits uint32) error {
	if e.authority.UID == 0 {
		return nil
	}
	residual, err := EvaluateACL(e.authority, entries(n), rights, n.Stat)
	if err != nil || residual == 0 {
		if errors.Is(err, syscall.EACCES) && OwnerOverride(e.authority, n.Stat) {
			return nil
		}
		return err
	}
	return e.posix(n, bits)
}

// Search authorizes traversal of one directory. A readonly mount prevents
// mutations, not lookup; no data-write authorization is requested here.
func (e *Evaluator) Search(ctx context.Context, directory Node) error {
	if err := validateNode(ctx, directory); err != nil {
		return err
	}
	if directory.Stat.Mode&0170000 != 0040000 {
		return syscall.ENOTDIR
	}
	return e.simple(directory, Search, 1)
}

func (e *Evaluator) writable(n Node, appendAllowed bool, ownerOverride bool) error {
	if n.Mount.Flags&1 != 0 {
		return syscall.EROFS
	}
	mask := uint32(0x00020002)
	if !appendAllowed {
		mask |= 0x00040004
	}
	if ownerOverride && OwnerOverride(e.authority, n.Stat) {
		mask &= 0xffff0000
	}
	if n.Stat.Flags&mask != 0 {
		return syscall.EPERM
	}
	return nil
}

// Create authorizes adding a file or subdirectory after parent search succeeds.
// ACL inheritance and creation mode are separate operations performed afterwards.
func (e *Evaluator) Create(ctx context.Context, parent Node, directory bool) error {
	if err := validateNode(ctx, parent); err != nil {
		return err
	}
	if parent.Stat.Mode&0170000 != 0040000 {
		return syscall.ENOTDIR
	}
	if err := e.writable(parent, true, true); err != nil {
		return err
	}
	rights := uint32(AddFile)
	if directory {
		rights = AddSubdirectory
	}
	return e.simple(parent, rights, 2)
}

// Delete authorizes removing a name. Leaf DELETE and parent DELETE_CHILD are
// distinct ordered decisions; explicit leaf permission precedes parent fallback,
// and an explicit parent grant precedes the POSIX/sticky-bit fallback.
func (e *Evaluator) Delete(ctx context.Context, parent, leaf Node) error {
	if err := validateNode(ctx, parent); err != nil {
		return err
	}
	if err := validateNode(ctx, leaf); err != nil {
		return err
	}
	if parent.Stat.Mode&0170000 != 0040000 {
		return syscall.ENOTDIR
	}
	if err := e.writable(leaf, false, true); err != nil {
		return err
	}
	if err := e.writable(parent, false, e.authority.UID == leaf.Stat.UID); err != nil {
		return err
	}
	if e.authority.UID == 0 {
		return nil
	}
	residual, err := EvaluateACL(e.authority, entries(leaf), Delete, leaf.Stat)
	if err != nil || residual == 0 {
		if errors.Is(err, syscall.EACCES) && OwnerOverride(e.authority, leaf.Stat) {
			return nil
		}
		return err
	}
	residual, err = EvaluateACL(e.authority, entries(parent), DeleteChild, parent.Stat)
	if err != nil || residual == 0 {
		if errors.Is(err, syscall.EACCES) && OwnerOverride(e.authority, parent.Stat) {
			return nil
		}
		return err
	}
	if err = e.posix(parent, 2); err != nil {
		return err
	}
	if parent.Stat.Mode&01000 != 0 && e.authority.UID != leaf.Stat.UID && e.authority.UID != parent.Stat.UID {
		return syscall.EACCES
	}
	return nil
}

// Rename authorizes ordinary rename after both names have been resolved. A nil
// destination records observed absence, not an unperformed destination lookup.
// Search, namespace existence/type checks and the actual rename remain caller
// operations. Mount identities prevent a cross-device move being silently allowed.
func (e *Evaluator) Rename(ctx context.Context, sourceParent, source, destinationParent Node, destination *Node) error {
	for _, node := range []Node{sourceParent, source, destinationParent} {
		if err := validateNode(ctx, node); err != nil {
			return err
		}
	}
	if destination != nil {
		if err := validateNode(ctx, *destination); err != nil {
			return err
		}
	}
	mount := source.Mount.Identity
	if sourceParent.Mount.Identity != mount || destinationParent.Mount.Identity != mount || destination != nil && destination.Mount.Identity != mount {
		return syscall.EXDEV
	}
	if destination != nil && source.Identity != 0 && source.Identity == destination.Identity {
		return nil
	}
	if err := e.Delete(ctx, sourceParent, source); err != nil {
		return err
	}
	if source.Stat.Mode&0170000 == 0040000 {
		if err := e.Create(ctx, source, true); err != nil {
			return err
		}
	}
	if err := e.Create(ctx, destinationParent, source.Stat.Mode&0170000 == 0040000); err != nil {
		return err
	}
	if destination != nil {
		return e.Delete(ctx, destinationParent, *destination)
	}
	return nil
}
