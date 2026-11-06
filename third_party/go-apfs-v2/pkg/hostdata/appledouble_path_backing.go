package hostdata

import (
	"errors"
	"os"
)

// A captured Darwin operation mutates logical metadata. Temporary receiving-host
// access is independent: retain and restore the actual backing inode's mode,
// never publish that host mode as a Darwin observation or a logical result.
type pathBackingAccess struct {
	file     *os.File
	mode     os.FileMode
	identity os.FileInfo
	nofollow bool
	changed  bool
}

func (p *appleDoublePath) prepareBackingAccess() error {
	if p.backing.file != nil {
		return nil
	}
	nofollow := p.options.NoFollowDestination || p.destinationObservation.NoFollowLink
	info, err := p.access.info(p.destinationName, nofollow)
	if err != nil {
		return err
	}
	// Windows FileInfo can load its file ID lazily from the pathname. Resolve it
	// before any permission change or reopen so a later replacement cannot supply
	// the identity that cleanup is meant to compare against.
	if !os.SameFile(info, info) {
		return ErrMetadataIdentity
	}
	p.backing.mode = info.Mode()
	p.backing.identity = info
	p.backing.nofollow = nofollow
	// Symlink metadata uses the logical carrier. Its receiving-host referent must
	// never be chmodded to emulate permission bits on a Darwin link itself.
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	file, err := p.access.open(p.destinationName, os.O_RDONLY, 0, nofollow, false, 0)
	if errors.Is(err, os.ErrPermission) {
		// The caller excludes path substitution; a read-denied owner can still
		// authorize this temporary opening. Retain restoration even if reopening
		// fails, then validate the acquired inode before any transfer.
		if err = p.access.chmod(p.destinationName, info.Mode()|0600); err != nil {
			return err
		}
		p.backing.changed = true
		file, err = p.access.open(p.destinationName, os.O_RDONLY, 0, nofollow, false, 0)
	}
	if err != nil {
		return err
	}
	p.backing.file = file
	held, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, held) || info.Mode().Type() != held.Mode().Type() {
		return ErrMetadataIdentity
	}
	if !p.backing.changed && info.Mode().Perm()&0600 != 0600 {
		if err = chmodPathBacking(file, info.Mode()|0600); err != nil {
			return err
		}
		p.backing.changed = true
	}
	return nil
}

func (p *appleDoublePath) closeBackingAccess() []HeldLifecycleStep {
	backing := p.backing
	p.backing = pathBackingAccess{}
	var steps []HeldLifecycleStep
	if backing.changed {
		var err error
		var current os.FileInfo
		if backing.file != nil {
			current, err = backing.file.Stat()
		} else {
			current, err = p.access.info(p.destinationName, backing.nofollow)
		}
		if err == nil && (!os.SameFile(backing.identity, current) || backing.identity.Mode().Type() != current.Mode().Type()) {
			err = ErrMetadataIdentity
		}
		if err == nil {
			if backing.file != nil {
				err = chmodPathBacking(backing.file, backing.mode)
			} else {
				err = p.access.chmod(p.destinationName, backing.mode)
			}
		}
		steps = append(steps, HeldLifecycleStep{Operation: "restore-backing-mode", Err: err})
	}
	if backing.file != nil {
		steps = append(steps, HeldLifecycleStep{Operation: "close-backing", Err: backing.file.Close()})
	}
	return steps
}
