package imageacl

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type statEntry struct {
	node     Node[*statEntry]
	metadata StatMetadata
	changed  bool
}

func statTree() (*statEntry, *statEntry, *statEntry) {
	times := hostdata.FileTimes{Birth: time.Unix(1, 0), Modify: time.Unix(2, 0), Change: time.Unix(3, 0), Access: time.Unix(4, 0)}
	flags := uint32(0x1800c0)
	a := &statEntry{node: Node[*statEntry]{UID: 41, GID: 42, Mode: 0106755, LinkGroup: 7, Xattrs: map[string][]byte{"keep": {1}}}, metadata: StatMetadata{Times: &times, Flags: &flags}}
	b := &statEntry{node: a.node, metadata: a.metadata}
	root := &statEntry{node: Node[*statEntry]{Mode: 040755, Children: []*statEntry{a, b}}}
	return root, a, b
}
func stageStat(root, target *statEntry, source hostdata.StatCopySource, options hostdata.StatCopyOptions, hfs bool) (hostdata.ImageStatCopyResult, error) {
	return CopyStat(root, target, source, options, hfs, func(e *statEntry, _ bool) (Node[*statEntry], error) { return e.node, nil }, func(e *statEntry) StatMetadata { return e.metadata }, func(e *statEntry, c StatChange) {
		e.changed = true
		e.node.UID, e.node.GID, e.node.Mode = c.UID, c.GID, c.Mode
		times, flags := c.Times, c.Flags
		e.metadata = StatMetadata{&times, &flags}
	})
}
func statSource() hostdata.StatCopySource {
	return hostdata.StatCopySource{UID: 51, GID: 52, Mode: 0106644, Flags: 0x1800c1, Times: hostdata.FileTimes{Modify: time.Unix(20, 1), Access: time.Unix(30, 2)}}
}
func TestImageStatStageAliases(t *testing.T) {
	for _, hfs := range []bool{false, true} {
		for _, options := range []hostdata.StatCopyOptions{{}, {ForbidCopySetID: true}, {MakeInvisible: true, PreserveDestinationTracked: true}} {
			root, a, b := statTree()
			oldTimes, oldFlags := *a.metadata.Times, *a.metadata.Flags
			r, e := stageStat(root, a, statSource(), options, hfs)
			if e != nil || !r.Applied || !r.Execution.Completed || !r.Execution.FlagsApplied || len(r.Execution.Failures) != 0 || !a.changed || !b.changed || root.changed {
				t.Fatal(r, e)
			}
			wantFlags := uint32(0x180081)
			if options.MakeInvisible {
				wantFlags |= 0x8000
			}
			if options.PreserveDestinationTracked {
				wantFlags |= 0x40
			}
			wantMode := uint16(0106644)
			if options.ForbidCopySetID {
				wantMode &^= 06000
			}
			for _, n := range []*statEntry{a, b} {
				if n.node.UID != 51 || n.node.GID != 52 || n.node.Mode != wantMode || *n.metadata.Flags != wantFlags || !reflect.DeepEqual(n.node.Xattrs, map[string][]byte{"keep": {1}}) {
					t.Fatal(n)
				}
				if !n.metadata.Times.Birth.Equal(oldTimes.Birth) || !n.metadata.Times.Change.Equal(oldTimes.Change) || !n.metadata.Times.Modify.Equal(statSource().Times.Modify) || !n.metadata.Times.Access.Equal(statSource().Times.Access) {
					t.Fatal(n.metadata)
				}
			}
			if a.metadata.Times == b.metadata.Times || a.metadata.Flags == b.metadata.Flags || oldFlags != 0x1800c0 {
				t.Fatal("shared output metadata")
			}
		}
	}
}
func TestImageStatStageRefusals(t *testing.T) {
	for _, hfs := range []bool{false, true} {
		for _, kind := range []string{"nil", "missing-times", "birth-range", "flag-compression", "alias-flags", "alias-birth", "alias-modify", "alias-change", "alias-access", "alias-security", "source-times", "source-compression", "options"} {
			t.Run(kind+map[bool]string{true: "-hfs", false: "-apfs"}[hfs], func(t *testing.T) {
				root, a, b := statTree()
				source := statSource()
				options := hostdata.StatCopyOptions{}
				switch kind {
				case "nil":
					root = nil
				case "missing-times":
					a.metadata.Times = nil
				case "birth-range":
					times := *a.metadata.Times
					times.Birth = time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
					a.metadata.Times = &times
				case "flag-compression":
					flags := uint32(0x20)
					a.metadata.Flags = &flags
				case "alias-flags":
					flags := uint32(1)
					b.metadata.Flags = &flags
				case "alias-birth", "alias-modify", "alias-change", "alias-access":
					times := *b.metadata.Times
					switch kind {
					case "alias-birth":
						times.Birth = times.Birth.Add(time.Second)
					case "alias-modify":
						times.Modify = times.Modify.Add(time.Second)
					case "alias-change":
						times.Change = times.Change.Add(time.Second)
					case "alias-access":
						times.Access = times.Access.Add(time.Second)
					}
					b.metadata.Times = &times
				case "alias-security":
					b.node.UID++
				case "source-times":
					source.Times.Access = time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
				case "source-compression":
					source.Flags = 0x20
				case "options":
					options.SourceNoSetID = true
					options.VolumePolicy = statPolicy{err: errors.New("must not query")}
				}
				beforeA, beforeB := *a, *b
				r, e := stageStat(root, a, source, options, hfs)
				if kind == "source-times" || kind == "source-compression" {
					if e != nil || !r.Execution.Completed || len(r.Execution.Failures) == 0 {
						t.Fatal(r, e)
					}
					for _, failure := range r.Execution.Failures {
						if !errors.Is(failure.Err, fs.ErrInvalid) {
							t.Fatal(failure)
						}
					}
				} else if !errors.Is(e, fs.ErrInvalid) {
					t.Fatal(r, e)
				}
				if r.Applied || !reflect.DeepEqual(*a, beforeA) || !reflect.DeepEqual(*b, beforeB) {
					t.Fatal("partial publication", r)
				}
			})
		}
	}
}

type statPolicy struct{ err error }

func (p statPolicy) NoSetID(hostdata.SecurityCopyVolume) (bool, error) { return false, p.err }
func TestImageStatStageSentinelsAndQueries(t *testing.T) {
	root, a, b := statTree()
	times := *b.metadata.Times
	times.Birth = times.Birth.In(time.FixedZone("same instant", 3600))
	b.metadata.Times = &times
	source := statSource()
	source.UID, source.GID = 0xffffffff, 0xffffffff
	source.Mode = 0
	sentinel := errors.New("volume lookup failed")
	r, e := stageStat(root, a, source, hostdata.StatCopyOptions{VolumePolicy: statPolicy{sentinel}}, false)
	if e != nil || !r.Applied || a.node.UID != 41 || a.node.GID != 42 || a.node.Mode != 0100000 || len(r.Execution.VolumeQueries) != 2 {
		t.Fatal(r, e, a.node)
	}
	for _, query := range r.Execution.VolumeQueries {
		if !errors.Is(query.Err, sentinel) {
			t.Fatal(query)
		}
	}
}
func TestImageStatPrivateCAS(t *testing.T) {
	c := &statCopier{StatChange: StatChange{Flags: 1}}
	actual, e := c.CompareAndSwapFlags(0, 2)
	if e != nil || actual != 1 || c.Flags != 1 {
		t.Fatal(actual, e, c.Flags)
	}
}
