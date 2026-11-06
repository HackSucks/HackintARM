package imageacl

import (
	"bytes"
	"maps"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// Change contains the staged security fields. ModeSelected distinguishes an
// omitted mode from an explicitly selected zero. Write only assigns these fields.
type Change struct {
	UID, GID     uint32
	Mode         uint16
	ModeSelected bool
	Xattrs       map[string][]byte
}

// Copy stages the ordinary security-copy sequence in a validated image tree.
// It shares target/alias binding with Restore. There is no native authorization,
// fallback capability failure or timestamp synthesis in an offline image tree.
func Copy[T comparable](root, target T, source hostdata.SecurityCopySource, options hostdata.SecurityCopyOptions, read func(T, bool) (Node[T], error), write func(T, Change)) (hostdata.SecurityCopyResult, error) {
	if !options.ACL && !options.Stat {
		return hostdata.CopySecurity(source, options, nil)
	}
	if source.Properties.RemoveACL {
		return hostdata.SecurityCopyResult{}, appledouble.ErrFileSecurity
	}
	if _, err := source.Properties.ChmodArguments(); err != nil {
		return hostdata.SecurityCopyResult{}, err
	}
	return stageCopy(root, target, read, write, func(backend *copier) (hostdata.SecurityCopyResult, error) {
		return hostdata.CopySecurity(source, options, backend)
	})
}

func stageCopy[T comparable](root, target T, read func(T, bool) (Node[T], error), write func(T, Change), execute func(*copier) (hostdata.SecurityCopyResult, error)) (hostdata.SecurityCopyResult, error) {
	aliases, nodes, destination, err := bind(root, target, read)
	if err != nil {
		return hostdata.SecurityCopyResult{}, err
	}
	backend := &copier{Change: Change{UID: destination.UID, GID: destination.GID, Mode: destination.Mode, Xattrs: destination.Xattrs}}
	result, err := execute(backend)
	if err != nil || len(result.Failures) != 0 {
		return result, err
	}
	prepared := make([]Change, len(aliases))
	for i, entry := range aliases {
		change := backend.Change
		change.Xattrs = nodes[entry].Xattrs
		if backend.securitySelected {
			change.Xattrs = maps.Clone(change.Xattrs)
			if change.Xattrs == nil {
				change.Xattrs = map[string][]byte{}
			}
			if backend.output == nil {
				delete(change.Xattrs, hostdata.SecurityName)
			} else {
				change.Xattrs[hostdata.SecurityName] = bytes.Clone(backend.output)
			}
		}
		prepared[i] = change
	}
	for i, entry := range aliases {
		write(entry, prepared[i])
	}
	return result, nil
}

type copier struct {
	Change
	securitySelected bool
	output           []byte
}

func (c *copier) CaptureDestinationACL() (*appledouble.ACL, error) {
	raw, present := c.Xattrs[hostdata.SecurityName]
	if present && raw == nil {
		raw = []byte{}
	}
	snapshot := hostdata.DecodeImageSecurity(c.UID, c.GID, c.Mode, raw)
	if snapshot.Source.Properties.RawSecurity == nil {
		return nil, nil
	}
	return snapshot.Source.Properties.RawSecurity.ACL, nil
}

func (c *copier) WriteSecurity(args aclmeta.DarwinChmodArguments) error {
	if args.SecurityArgument != aclmeta.DarwinSecurityNone {
		var acl *appledouble.ACL
		var flags [4]byte
		if args.SecurityArgument == aclmeta.DarwinSecurityRecord {
			security, err := appledouble.ParseDarwinFileSecurity(args.Security)
			if err != nil {
				return err
			}
			acl, flags = security.ACL, security.NoACLFlags
		}
		if err := c.setSecurity(acl, flags); err != nil {
			return err
		}
	}
	if args.UID != 0xffffff9b {
		c.UID = args.UID
	}
	if args.GID != 0xffffff9b {
		c.GID = args.GID
	}
	if args.Mode == -1 && (args.UID != 0xffffff9b || args.GID != 0xffffff9b) {
		c.clearSetID()
	}
	if args.Mode != -1 {
		return c.Chmod(uint16(args.Mode))
	}
	return nil
}
func (c *copier) Chmod(mode uint16) error {
	c.Mode = c.Mode&0170000 | mode&07777
	c.ModeSelected = true
	return nil
}
func (c *copier) clearSetID() {
	if c.Mode&06000 != 0 {
		c.Mode &^= 06000
		c.ModeSelected = true
	}
}
func (c *copier) Chown(uid, gid uint32) error {
	if uid != 0xffffffff || gid != 0xffffffff {
		c.clearSetID()
	}
	if uid != 0xffffffff {
		c.UID = uid
	}
	if gid != 0xffffffff {
		c.GID = gid
	}
	return nil
}
func (c *copier) SetACL(acl *appledouble.ACL) error { return c.setSecurity(acl, [4]byte{}) }
func (c *copier) setSecurity(acl *appledouble.ACL, flags [4]byte) error {
	// Extended chmod selects va_acl only: UUID arguments do not replace the
	// stored UUID slots. Invalid stored records supply no UUID ownership.
	record := &appledouble.FileSecurity{ACL: acl, NoACLFlags: flags}
	raw := c.Xattrs[hostdata.SecurityName]
	if hostdata.SecurityRecordSizeValid(uint64(len(raw))) {
		if stored, err := appledouble.ParseFileSecurity(raw); err == nil {
			record.OwnerUUID, record.GroupUUID = stored.OwnerUUID, stored.GroupUUID
		}
	}
	var output []byte
	if acl != nil || record.OwnerUUID != [16]byte{} || record.GroupUUID != [16]byte{} {
		var err error
		output, err = record.MarshalBinary()
		if err != nil {
			return err
		}
	}
	c.securitySelected, c.output = true, output
	return nil
}
