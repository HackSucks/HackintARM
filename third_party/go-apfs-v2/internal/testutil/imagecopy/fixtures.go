// Package imagecopy supplies shared native/portable ordinary security cases.
package imagecopy

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagerestore"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type Case struct {
	Name, Target string
	Aliases      []string
	Source       hostdata.SecurityCopySource
	Options      hostdata.SecurityCopyOptions
}
type Tree struct {
	Name  string
	Root  *apfswrite.Entry
	Cases []Case
}
type Observation struct {
	imagerestore.Observation
	Events []securitycopy.Event
	Cache  securitycopy.Properties
}
type NativeCase struct {
	GoError         string
	Filesystem      string
	Case            Case
	Native, Written Observation
	GoResult        hostdata.SecurityCopyResult
}
type Fixture struct {
	Revision, Host                                             string
	ActorUID, ActorGID                                         uint32
	Sources, Helpers, InitialImages, NativeImages, FinalImages map[string]string
	Cases                                                      []NativeCase
	Aliases                                                    map[string]Observation
}

func Sources(uid, gid uint32) []hostdata.SecurityCopySource {
	var result []hostdata.SecurityCopySource
	for i := 0; i < 7; i++ {
		mode := uint32(0106711)
		if i == 0 {
			mode = 0100000
		}
		s := hostdata.SecurityCopySource{UID: uid, GID: gid, Mode: mode}
		mask := []int{7, 0, 3, 4, 1, 2, 7}[i]
		if mask&1 != 0 {
			v := uid
			s.Properties.UID = &v
		}
		if mask&2 != 0 {
			v := gid
			s.Properties.GID = &v
		}
		if mask&4 != 0 {
			v := mode
			s.Properties.Mode = &v
		}
		if i != 0 {
			record := &appledouble.FileSecurity{}
			if i == 6 {
				record.NoACLFlags = [4]byte{1, 2, 3, 4}
			} else {
				record.ACL = &appledouble.ACL{Flags: 1 << 17}
				count := []int{0, 0, 0, 1, 2, 127, 0}[i]
				for j := 0; j < count; j++ {
					flags := uint32(1)
					if i == 4 && j == 1 {
						flags = 17
					}
					record.ACL.Entries = append(record.ACL.Entries, appledouble.ACLEntry{Principal: [16]byte{0x11, 0x23, byte(j + 1)}, Flags: flags, Rights: 1})
				}
			}
			if i != 2 {
				s.Properties.RawSecurity = record
			}
			if i%2 == 0 {
				s.Properties.OwnerUUID = &[16]byte{0x33}
				s.Properties.GroupUUID = &[16]byte{0x44}
			}
		}
		result = append(result, s)
	}
	return result
}
func Trees(uid, gid uint32) []Tree {
	root := &apfswrite.Entry{Mode: os.ModeDir | 0755, ModeExplicit: true, UID: uid, GID: gid, Xattrs: map[string][]byte{"user.unrelated": []byte("root")}}
	profiles := imagesecurity.Profiles()
	selected := []imagesecurity.Profile{profiles[0], profiles[1], profiles[4], profiles[5], profiles[7], profiles[16], profiles[22]}
	inherited := appledouble.FileSecurity{OwnerUUID: [16]byte{0x11}, GroupUUID: [16]byte{0x22}, ACL: &appledouble.ACL{Flags: 1 << 17, Entries: []appledouble.ACLEntry{{Principal: [16]byte{0x55}, Flags: 17, Rights: 1}}}}
	b, err := inherited.MarshalBinary()
	if err != nil {
		panic(err)
	}
	selected = append(selected, imagesecurity.Profile{Name: "inherited", Data: b})
	var cases []Case
	var group uint64
	for d, p := range selected {
		for s, source := range Sources(uid, gid) {
			for stage := 0; stage < 3; stage++ {
				for _, kind := range []string{"file", "directory", "symlink", "hardlink"} {
					name := fmt.Sprintf("%s-s%d-stage%d-%s", p.Name, s, stage, kind)
					mode := os.FileMode(0755) | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
					if d%3 == 0 {
						mode = 0
					}
					entry := &apfswrite.Entry{Name: name, Mode: mode, ModeExplicit: true, UID: uid, GID: gid, Data: []byte("payload"), Xattrs: map[string][]byte{"user.unrelated": []byte("retained")}}
					if p.Data != nil {
						entry.Xattrs[hostdata.SecurityName] = append([]byte{}, p.Data...)
					}
					options := hostdata.SecurityCopyOptions{DestinationNoSetID: true, ACL: stage != 1, Stat: stage != 0}
					policy := (d + s + stage) % 3
					options.ForbidCopySetID = policy != 0
					options.AlwaysCopySetID = policy == 2
					c := Case{Name: name, Target: name, Source: source, Options: options}
					switch kind {
					case "directory":
						entry.Mode |= os.ModeDir
						entry.Data = nil
					case "symlink":
						entry.Mode |= os.ModeSymlink
						entry.Data = []byte("missing-target")
					case "hardlink":
						group++
						entry.LinkGroup = group
						entry.Name += "-a"
						alias := *entry
						alias.Name = name + "-b"
						root.Children = append(root.Children, &alias)
						c.Target = alias.Name
						c.Aliases = []string{entry.Name}
					}
					root.Children = append(root.Children, entry)
					cases = append(cases, c)
				}
			}
		}
	}
	zero := &apfswrite.Entry{Mode: os.ModeDir, ModeExplicit: true, UID: uid, GID: gid}
	return []Tree{{Name: "entries", Root: root, Cases: cases}, {Name: "root-zero", Root: zero, Cases: []Case{{Name: "root-zero", Target: ".", Source: Sources(uid, gid)[3], Options: hostdata.SecurityCopyOptions{DestinationNoSetID: true, ACL: true, Stat: true}}}}}
}
func ApplyAPFS(root *apfswrite.Entry, c Case) (hostdata.SecurityCopyResult, error) {
	target := root
	if c.Target != "." {
		target = nil
		for _, e := range root.Children {
			if e.Name == c.Target {
				target = e
			}
		}
	}
	if target == nil {
		return hostdata.SecurityCopyResult{}, fmt.Errorf("missing target %s", c.Target)
	}
	return root.CopySecurity(target, c.Source, c.Options)
}
func ApplyHFS(root *hfsplus.Entry, c Case) (hostdata.SecurityCopyResult, error) {
	target := root
	if c.Target != "." {
		target = nil
		for _, e := range root.Children {
			if e.Name == c.Target {
				target = e
			}
		}
	}
	if target == nil {
		return hostdata.SecurityCopyResult{}, fmt.Errorf("missing target %s", c.Target)
	}
	return root.CopySecurity(target, c.Source, c.Options)
}

// Packet supplies captured properties to the native filesec constructor.
func Packet(c Case) []byte {
	p := c.Source.Properties
	mask := 0
	var mode uint32
	if p.UID != nil {
		mask |= 1
	}
	if p.GID != nil {
		mask |= 2
	}
	if p.Mode != nil {
		mask |= 4
		mode = *p.Mode
	}
	options := 0
	if c.Options.ACL {
		options |= 1
	}
	if c.Options.Stat {
		options |= 2
	}
	if c.Options.ForbidCopySetID {
		options |= 4
	}
	if c.Options.AlwaysCopySetID {
		options |= 8
	}
	owner, group, raw := "-", "-", "-"
	if p.OwnerUUID != nil {
		owner = fmt.Sprintf("%x", *p.OwnerUUID)
	}
	if p.GroupUUID != nil {
		group = fmt.Sprintf("%x", *p.GroupUUID)
	}
	if p.RawSecurity != nil {
		b, e := p.RawSecurity.MarshalDarwinBinary()
		if e != nil {
			panic(e)
		}
		raw = fmt.Sprintf("%x", b)
	}
	return []byte(fmt.Sprintf("%d %d %d %d %d %d %s %s %s\n", c.Source.UID, c.Source.GID, c.Source.Mode, mask, mode, options, owner, group, raw))
}
