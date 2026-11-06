package hostdata

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type pathInputValue struct {
	*os.File
	length int64
}

// Keep host filesystem effects at one boundary. Qualification injects failures
// and identity changes here while running the same acquisition state machine.
type pathAccessOps struct {
	info     func(string, bool) (os.FileInfo, error)
	open     func(string, int, uint32, bool, bool, int) (*os.File, error)
	mkdir    func(string, os.FileMode) error
	readlink func(string) (string, error)
	symlink  func(string, string) error
	unlink   func(string) error
	chmod    func(string, os.FileMode) error
}

func defaultPathAccessOps() pathAccessOps {
	return pathAccessOps{pathInfo, openPathPayload, os.Mkdir, os.Readlink, os.Symlink, os.Remove, os.Chmod}
}

func (v pathInputValue) Size() int64 { return v.length }

func (p *appleDoublePath) Open(ctx context.Context, attempts uint64) (result PathOpenResult, err error) {
	step := func(name string, e error) {
		result.Steps = append(result.Steps, HeldLifecycleStep{Operation: name, Err: e})
	}
	p.sourceMetadata, err = p.capture(p.sourceName, true, p.options.NoFollowSource)
	step("source-security", err)
	if err != nil {
		return result, err
	}
	kind := p.sourceMetadata.State.Stat.Mode & 0170000
	nullSource := p.sourceName == os.DevNull && kind == 0020000
	if kind != 0100000 && kind != 0040000 && kind != 0120000 && !nullSource {
		return result, errors.ErrUnsupported
	}
	before, err := p.access.info(p.sourceName, p.options.NoFollowSource)
	if err != nil {
		return result, err
	}
	if IsSpecial(before.Mode()) && !nullSource {
		return result, errors.ErrUnsupported
	}
	if pathModeType(before.Mode()) != kind {
		return result, ErrMetadataIdentity
	}
	p.sourceFile, err = p.access.open(p.sourceName, os.O_RDONLY, 0, p.options.NoFollowSource, false, 0)
	step("open-source", err)
	if err != nil {
		return result, err
	}
	held, err := p.sourceFile.Stat()
	step("source-stat", err)
	if err != nil {
		return result, err
	}
	if !os.SameFile(before, held) || before.Mode().Type() != held.Mode().Type() {
		return result, ErrMetadataIdentity
	}
	if identity, ok := p.native.identity(held); ok && (identity.Device != p.sourceMetadata.Identity.Device || identity.Inode != p.sourceMetadata.Identity.Inode) {
		return result, ErrMetadataIdentity
	}
	repeated, err := p.access.info(p.sourceName, p.options.NoFollowSource)
	step("source-repeat-type", err)
	if err != nil {
		return result, err
	}
	if repeated.Mode().Type() != before.Mode().Type() {
		return result, ErrMetadataIdentity
	}
	if p.options.Captured != nil {
		p.source = p.options.Captured.Source
	} else {
		p.source, err = p.native.bind(ctx, p.sourceFile)
	}
	if err != nil {
		return result, err
	}
	p.source.stat = p.sourceMetadata.State.Stat
	p.quarantine, err = p.source.attrs.quarantine(ctx, p.source.process.Profile)
	step("quarantine-capture", err)
	result.Steps = append(result.Steps, p.openSourceFork()...)
	// Quarantine acquisition errors are retained and ignored by copyfile_open.
	if e := ctx.Err(); e != nil {
		return result, e
	}
	if p.options.UnlinkDestination {
		e := p.access.unlink(p.destinationName)
		step("unlink-destination", e)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return result, e
		}
		if p.options.Captured != nil {
			p.options.Captured.Destination = nil
		}
	}
	supported, class, err := p.sourceProtection()
	step("source-protection", err)
	if err != nil {
		return result, err
	}
	if p.options.DontSetProtection || !p.protectionEligible() {
		class = -1
	}
	createKind := kind
	if p.options.Operation == PathPackAppleDouble || nullSource {
		createKind = 0100000
	}
	created, explicitClass := false, false
	if createKind == 0040000 {
		e := p.access.mkdir(p.destinationName, pathFileMode(uint16(p.sourceMetadata.State.Stat.Mode)|0700))
		step("create-directory", e)
		if e != nil && (!errors.Is(e, os.ErrExist) || p.options.Exclusive) {
			return result, e
		}
		created = e == nil
		p.destinationFile, err = p.access.open(p.destinationName, os.O_RDONLY, 0, p.options.NoFollowDestination, false, 0)
		explicitClass = true
	} else if createKind == 0120000 {
		link, e := p.access.readlink(p.sourceName)
		if e != nil {
			return result, e
		}
		e = p.access.symlink(link, p.destinationName)
		step("create-symlink", e)
		if e != nil && (!errors.Is(e, os.ErrExist) || p.options.Exclusive) {
			return result, e
		}
		created = e == nil
		p.destinationFile, err = p.access.open(p.destinationName, os.O_RDONLY, 0, true, false, 0)
	} else {
		flags := os.O_CREATE | os.O_EXCL | os.O_RDONLY
		if p.options.Operation == PathPackAppleDouble {
			flags = os.O_CREATE | os.O_EXCL | os.O_WRONLY
		}
		for n := uint64(0); ; n++ {
			if err = ctx.Err(); err != nil {
				return result, err
			}
			if n == attempts {
				return result, ErrPathWorkLimit
			}
			p.destinationFile, err = p.access.open(p.destinationName, flags, p.sourceMetadata.State.Stat.Mode|0200, p.options.NoFollowDestination, p.options.Captured == nil, class)
			step("open-destination", err)
			if err == nil {
				created = flags&os.O_CREATE != 0
				break
			}
			switch {
			case errors.Is(err, os.ErrExist):
				if p.options.Exclusive {
					return result, err
				}
				flags &^= os.O_CREATE
				explicitClass = true
				if p.options.Operation == PathPackAppleDouble {
					flags |= os.O_TRUNC
				}
			case errors.Is(err, syscall.EISDIR):
				if p.options.Exclusive && p.options.Operation != PathUnpackAppleDouble {
					return result, err
				}
				flags &^= os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			default:
				return result, err
			}
		}
	}
	if err != nil {
		step("open-destination", err)
		return result, err
	}
	if p.options.Captured != nil {
		if created {
			err = p.createCapturedDestination(createKind)
		}
		p.destination = p.options.Captured.Destination
		if err == nil && p.destination == nil {
			err = fmt.Errorf("missing captured destination: %w", os.ErrInvalid)
		}
	} else {
		p.destination, err = p.native.bind(ctx, p.destinationFile)
	}
	if err != nil {
		return result, err
	}
	if supported {
		assign := explicitClass || (p.options.Captured != nil && created && createKind == 0100000)
		err = p.destinationProtection(class, assign && !p.options.DontSetProtection && p.protectionEligible())
		step("destination-protection", err)
		if err != nil {
			return result, err
		}
	}
	result.Steps = append(result.Steps, p.openDestinationFork()...)
	return result, nil
}

func pathInfo(name string, nofollow bool) (os.FileInfo, error) {
	if nofollow {
		return os.Lstat(name)
	}
	return os.Stat(name)
}
func pathFileMode(mode uint16) os.FileMode {
	m := os.FileMode(mode & 0777)
	if mode&04000 != 0 {
		m |= os.ModeSetuid
	}
	if mode&02000 != 0 {
		m |= os.ModeSetgid
	}
	if mode&01000 != 0 {
		m |= os.ModeSticky
	}
	return m
}
func (p *appleDoublePath) protectionEligible() bool {
	kind := p.sourceMetadata.State.Stat.Mode & 0170000
	return kind == 0100000 || (kind == 0040000 && p.options.Operation != PathPackAppleDouble)
}
func (p *appleDoublePath) sourceProtection() (bool, int, error) {
	if c := p.options.Captured; c != nil {
		if c.SourceProtection == nil {
			return false, 0, fmt.Errorf("source protection observation missing: %w", os.ErrInvalid)
		}
		if !c.SourceProtection.Supported {
			return false, -1, nil
		}
		return c.SourceProtection.Supported, c.SourceProtection.Class, nil
	}
	supported, err := p.native.protection(p.sourceFile)
	if err != nil || !supported || p.options.DontSetProtection || !p.protectionEligible() {
		return supported, -1, err
	}
	class, err := p.native.getClass(p.sourceFile)
	return supported, class, err
}
func (p *appleDoublePath) destinationProtection(class int, assign bool) error {
	if c := p.options.Captured; c != nil {
		if c.DestinationProtection == nil {
			return fmt.Errorf("destination protection observation missing: %w", os.ErrInvalid)
		}
		if c.DestinationProtection.Supported && assign {
			c.DestinationProtection.Class = class
		}
		return nil
	}
	supported, err := p.native.protection(p.destinationFile)
	if err != nil || !supported || !assign {
		return err
	}
	return p.native.setClass(p.destinationFile, class)
}
func (p *appleDoublePath) createCapturedDestination(kind uint32) error {
	creation := p.options.Captured.Creation
	if creation == nil {
		return fmt.Errorf("destination creation context missing for %s: %w", filepath.Base(p.destinationName), os.ErrInvalid)
	}
	seed := creation.Template
	mode := uint16(p.sourceMetadata.State.Stat.Mode) | 0200
	if kind == 0040000 {
		mode |= 0700
	} else if kind == 0120000 {
		// symlink(2) creates its own permissions; it does not receive the
		// source mode used by open(2) and mkdir(2).
		mode = 0777
	}
	mode &^= creation.Umask & 0777
	mode = (mode &^ 0170000) | uint16(kind)
	seed.State.Stat.Mode, seed.State.Security.Mode = uint32(mode), uint32(mode)
	modeValue := uint32(mode)
	seed.State.Security.Properties.Mode = &modeValue
	var initial *appledouble.ACL
	if raw := seed.State.Security.Properties.RawSecurity; raw != nil {
		initial = raw.ACL
	}
	inherited, err := appledouble.InheritACL(initial, creation.ParentACL, kind == 0040000)
	if err != nil {
		return err
	}
	if inherited != nil {
		raw := &appledouble.FileSecurity{}
		if seed.State.Security.Properties.RawSecurity != nil {
			*raw = *seed.State.Security.Properties.RawSecurity
		}
		raw.ACL = inherited
		raw.NoACLFlags = [4]byte{}
		seed.State.Security.Properties.RawSecurity = raw
	}
	object, err := NewCapturedAppleDoubleObject(seed)
	if err == nil {
		p.options.Captured.Destination = object
	}
	return err
}
