package imageacl

import (
	"fmt"
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/bsdflags"
	"github.com/deploymenttheory/go-apfs-v2/internal/inodetime"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// StatMetadata is explicit destination state. Times must be resolved by the
// caller: a tree alone cannot determine serialization defaults or clamp policy.
type StatMetadata struct {
	Times *hostdata.FileTimes
	Flags *uint32
}

// StatChange contains only selected stat fields; payloads and xattrs are untouched.
type StatChange struct {
	UID, GID, Flags uint32
	Mode            uint16
	Times           hostdata.FileTimes
}

// CopyStat binds the existing validated tree/alias graph, executes the shared
// stat stage against private metadata and publishes only a complete valid result.
// Callbacks and the caller must exclude concurrent tree mutation.
func CopyStat[T comparable](root, target T, source hostdata.StatCopySource, options hostdata.StatCopyOptions, hfs bool, read func(T, bool) (Node[T], error), metadata func(T) StatMetadata, write func(T, StatChange)) (result hostdata.ImageStatCopyResult, err error) {
	aliases, nodes, destination, err := bind(root, target, read)
	if err != nil {
		return result, err
	}
	var staged StatChange
	for i, entry := range aliases {
		m := metadata(entry)
		if m.Times == nil {
			return result, fmt.Errorf("image stat requires explicit destination Times: %w", fs.ErrInvalid)
		}
		if _, err := inodetime.Encode(*m.Times, time.Time{}, false, hfs); err != nil {
			return result, err
		}
		_, compressed := nodes[entry].Xattrs["com.apple.decmpfs"]
		flags, err := bsdflags.Select(m.Flags, compressed, hfs)
		if err != nil {
			return result, err
		}
		if i == 0 {
			staged = StatChange{UID: destination.UID, GID: destination.GID, Mode: destination.Mode, Flags: flags, Times: *m.Times}
		} else if flags != staged.Flags || !equalTimes(staged.Times, *m.Times) {
			return result, fmt.Errorf("image stat: conflicting hard-link timestamps or flags: %w", fs.ErrInvalid)
		}
	}
	_, compressed := destination.Xattrs["com.apple.decmpfs"]
	backend := &statCopier{StatChange: staged, hfs: hfs, compressed: compressed}
	result.Execution, err = hostdata.CopyStat(source, options, backend)
	if err != nil || len(result.Execution.Failures) != 0 {
		return result, err
	}
	for _, entry := range aliases {
		write(entry, backend.StatChange)
	}
	result.Applied = true
	return result, nil
}

func equalTimes(a, b hostdata.FileTimes) bool {
	return a.Birth.Equal(b.Birth) && a.Modify.Equal(b.Modify) && a.Change.Equal(b.Change) && a.Access.Equal(b.Access)
}

type statCopier struct {
	StatChange
	hfs, compressed bool
}

func (c *statCopier) SetTimes(modify, access time.Time) error {
	next := c.Times
	next.Modify, next.Access = modify, access
	if _, err := inodetime.Encode(next, time.Time{}, false, c.hfs); err != nil {
		return err
	}
	c.Times = next
	return nil
}
func (c *statCopier) Chown(uid, gid uint32) error {
	if uid != 0xffffffff {
		c.UID = uid
	}
	if gid != 0xffffffff {
		c.GID = gid
	}
	return nil
}
func (c *statCopier) Chmod(mode uint16) error {
	c.Mode = c.Mode&0170000 | mode&07777
	return nil
}
func (c *statCopier) ReadFlags() (uint32, error) { return c.Flags, nil }
func (c *statCopier) CompareAndSwapFlags(expected, replacement uint32) (uint32, error) {
	actual := c.Flags
	if actual != expected {
		return actual, nil
	}
	return actual, c.Chflags(replacement)
}
func (c *statCopier) Chflags(flags uint32) error {
	if _, err := bsdflags.Select(&flags, c.compressed, c.hfs); err != nil {
		return err
	}
	c.Flags = flags
	return nil
}
