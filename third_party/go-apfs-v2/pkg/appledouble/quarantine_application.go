package appledouble

import (
	"errors"
	"fmt"
	"strings"
)

// ErrQuarantineContext means process state is unavailable or outside the
// independently qualified application contexts. It must not imply no quarantine.
var ErrQuarantineContext = errors.New("appledouble: unqualified quarantine process context")

// ErrQuarantineApplicationSize identifies the native application buffer limit.
// An envelope can be valid for serialization yet too large for application.
var ErrQuarantineApplicationSize = errors.New("appledouble: quarantine application value exceeds buffer")

// ErrQuarantineMissing identifies application that requires an existing
// quarantine attribute but finds none (the qualified native ENOATTR outcome).
var ErrQuarantineMissing = errors.New("appledouble: quarantine application requires an existing attribute")

// ErrQuarantineExisting identifies the native EINVAL outcome when application
// needs the destination's numeric quarantine header but cannot interpret it.
// Other operations can replace or preserve the same malformed bytes successfully.
var ErrQuarantineExisting = errors.New("appledouble: quarantine application requires a valid existing header")

// ErrQuarantineDestination identifies an unknown or contradictory destination
// kind. It applies equally on every Go operating system.
var ErrQuarantineDestination = errors.New("appledouble: unqualified quarantine destination kind")

// QuarantineDestinationKind describes the object receiving metadata, independent
// of the Go host. A symlink means the link itself, never its target.
type QuarantineDestinationKind uint8

const (
	// QuarantineRegularFile is the default destination kind.
	QuarantineRegularFile QuarantineDestinationKind = iota
	// QuarantineDirectory selects native directory timestamp behavior.
	QuarantineDirectory
	// QuarantineSymlink applies to the link itself, including dangling links.
	QuarantineSymlink
)

// MaxQuarantineApplicationSize is the largest canonical plain value accepted
// before native application. This is distinct from MaxQuarantineXattrSize.
const MaxQuarantineApplicationSize = 381

// QuarantineProcess supplies known effective flags and the raw kernel agent,
// or explicitly confirmed label absence with Absent.
// Agent is byte data, not an escaped field. Native process snapshots can lose
// backslash bytes; callers must resolve the raw agent independently when that
// happens. Requested flags cannot substitute for captured effective flags, and
// a refused process change cannot supply either field.
type QuarantineProcess struct {
	Flags uint32
	Agent string
	// Absent means a valid process-info query confirmed no quarantine label.
	// It is distinct from unavailable capture (nil Process) or successful capture
	// with zero flags. Flags and Agent must be empty. This context is currently
	// qualified for both profiles on every Go operating system.
	Absent bool
}

// QuarantineApplicationContext supplies policy inputs independently of the Go
// host. Process must be known; nil is unavailable, not unquarantined. Qualified
// process flags are 0x001 through 0x01f for macOS 26 and 0x200 through 0x21f for macOS
// 27, whose confirmed initially unlabelled processes also use 0x001..0x01f.
// Confirmed Absent state is qualified for both profiles. Other contexts require
// further native qualification.
//
// Existing describes the actual prepared destination, after cleanup or baseline
// writes. Alternatively, ExistingXattr supplies its exact filesystem bytes,
// including malformed values: nil means absent and a non-nil empty slice means
// present with zero bytes. Supply at most one representation. With neither set,
// attribute absence is confirmed. Timestamp is an injected Unix
// time in seconds, used when policy refreshes a file or symlink's timestamp.
// Kind selects the receiving object. Directory retains the original directory
// selector: true with a zero Kind selects a directory; true with a symlink Kind
// is contradictory. Other object kinds require qualification. This type grants
// no filesystem permission and never follows or resolves a path.
type QuarantineApplicationContext struct {
	Profile       QuarantineProfile
	Process       *QuarantineProcess
	Existing      *Quarantine
	ExistingXattr []byte
	Kind          QuarantineDestinationKind
	Directory     bool
	Timestamp     uint32
}

// QuarantineApplication requests either an exact xattr write or preservation.
// With Write false, preserve the original raw attribute (including absence);
// Value is nil. Value with Write true is the exact plain filesystem value, not
// an AppleDouble envelope and not necessarily a canonical serialized model.
// Kernel agent insertion and identifier truncation can change its interpretation.
type QuarantineApplication struct {
	Write bool
	Value []byte
}

// PlanApplication reproduces qualified direct quarantine application policy in
// pure Go. It does not access a filesystem, capture process state, read the clock,
// or perform copyfile's preceding cleanup. Feed valid ordered QuarantineUpdates
// through this operation using the destination state at each record's position.
//
// Errors do not request a write. Invalid source/existing models or profiles return
// ErrQuarantine. Unknown process context, application size and missing-attribute
// outcomes have distinct sentinel errors. Actual transport permission/I/O errors
// and copyfile callback decisions still belong to the caller.
func (q *Quarantine) PlanApplication(ctx QuarantineApplicationContext) (*QuarantineApplication, error) {
	envelope, err := q.MarshalBinaryWithProfile(ctx.Profile)
	if err != nil {
		return nil, err
	}
	if ctx.Existing != nil {
		if ctx.ExistingXattr != nil {
			return nil, ErrQuarantine
		}
		if _, err := ctx.Existing.MarshalBinaryWithProfile(ctx.Profile); err != nil {
			return nil, err
		}
	}
	if !qualifiedQuarantineProcess(ctx.Profile, ctx.Process) {
		return nil, ErrQuarantineContext
	}
	if ctx.Kind > QuarantineSymlink || (ctx.Directory && ctx.Kind == QuarantineSymlink) {
		return nil, ErrQuarantineDestination
	}
	raw := envelope[2 : len(envelope)-1]
	if len(raw) > MaxQuarantineApplicationSize {
		return nil, ErrQuarantineApplicationSize
	}
	flags := q.Flags
	if flags == 0 {
		flags = 1
	}
	if ctx.Process.Absent {
		if ctx.Profile == QuarantineMacOS27 {
			flags &^= 0x218
			if flags == 0 {
				return &QuarantineApplication{}, nil
			}
		}
		// Without a process label, native preserves the encoded source fields,
		// full identifier and original timestamp even for directories.
		copy(raw[:4], fmt.Sprintf("%04x", normalizedQuarantineApplicationFlags(flags)))
		return &QuarantineApplication{Write: true, Value: raw}, nil
	}
	sandbox := ctx.Process.Flags&2 != 0
	existingFlags, existingValid := uint32(0), true
	existingPresent := ctx.Existing != nil || ctx.ExistingXattr != nil
	if sandbox {
		flags &^= 0x60
		if ctx.Existing != nil {
			existingFlags = ctx.Existing.Flags
		} else if ctx.ExistingXattr != nil {
			existingFlags, existingValid = quarantineExistingHeader(ctx.ExistingXattr)
		}
		if existingValid {
			flags |= existingFlags & 6
		}
		if flags == 0 {
			// This native fallback keeps the input's encoded fields and timestamp,
			// including the full identifier, rather than performing kernel substitution.
			copy(raw[:4], "0081")
			return &QuarantineApplication{Write: true, Value: raw}, nil
		}
	}
	if ctx.Profile == QuarantineMacOS27 {
		flags &^= 0x218
	}
	if flags == 0 {
		if sandbox {
			if !existingPresent {
				return nil, ErrQuarantineMissing
			}
			if !existingValid {
				return nil, ErrQuarantineExisting
			}
		}
		return &QuarantineApplication{}, nil
	}
	flags = normalizedQuarantineApplicationFlags(flags)
	timestamp := ctx.Timestamp
	if ctx.Directory || ctx.Kind == QuarantineDirectory {
		timestamp = 0
	}
	value := fmt.Appendf(nil, "%04x;%08x;", flags, timestamp)
	value = append(value, ctx.Process.Agent...)
	value = append(value, ';')
	identifier := escapeQuarantine(nil, q.Identifier)
	// Native truncates encoded bytes, even partway through a four-byte escape.
	value = append(value, identifier[:min(len(identifier), 63)]...)
	return &QuarantineApplication{Write: true, Value: value}, nil
}

// Native application consumes two numeric assignments, not a libquarantine
// import. Field lengths, flag masks and the trailing text are irrelevant here.
// Reuse the codec's scanner without normalizing zero or validating the envelope.
func quarantineExistingHeader(data []byte) (uint32, bool) {
	s := string(data)
	if n := strings.IndexByte(s, 0); n >= 0 {
		s = s[:n]
	}
	// XNU's scanner skips space, tab and LF, unlike libc's six ASCII spaces.
	flags, pos, ok := quarantineHexSpace(s, 0, 4, " \t\n")
	if !ok || pos >= len(s) || s[pos] != ';' {
		return 0, false
	}
	_, _, ok = quarantineHexSpace(s, pos+1, 8, " \t\n")
	return flags, ok
}

func qualifiedQuarantineProcess(profile QuarantineProfile, p *QuarantineProcess) bool {
	if p == nil || len(p.Agent) > 255 || strings.IndexByte(p.Agent, 0) >= 0 {
		return false
	}
	if p.Absent {
		return (profile == QuarantineMacOS26 || profile == QuarantineMacOS27) && p.Flags == 0 && p.Agent == ""
	}
	switch profile {
	case QuarantineMacOS26:
		return p.Flags >= 1 && p.Flags <= 0x1f
	case QuarantineMacOS27:
		return p.Flags >= 1 && p.Flags <= 0x1f || p.Flags >= 0x200 && p.Flags <= 0x21f
	default:
		return false
	}
}

func normalizedQuarantineApplicationFlags(flags uint32) uint32 {
	if flags&3 != 0 && flags&0x40 == 0 {
		flags |= 0x80
	}
	return flags
}
