// Package imagerestore supplies shared native/portable image restoration cases.
package imagerestore

import (
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

type Case struct {
	Name, Target string
	Text         []byte
	Aliases      []string
}
type Tree struct {
	Name  string
	Root  *apfswrite.Entry
	Cases []Case
}
type Metadata struct {
	Security              string
	UID, GID, Mode, Flags uint32
}
type Observation struct {
	Before, After                             Metadata
	BeforeAttributes, AfterAttributes         string
	Code, Errno                               int
	TemporaryReadSetup, Applied, SameIdentity bool
	Inode                                     uint64
}
type NativeCase struct {
	Filesystem      string
	Case            Case
	Native, Written Observation
	GoResult        aclmeta.ACLRestoreResult
}
type Fixture struct {
	Revision, Host                                             string
	ActorUID, ActorGID                                         uint32
	Sources, Helpers, InitialImages, NativeImages, FinalImages map[string]string
	Cases                                                      []NativeCase
	Aliases                                                    map[string]Observation
}

func Trees(uid, gid uint32) []Tree {
	root := &apfswrite.Entry{Mode: os.ModeDir | 0755, ModeExplicit: true, UID: uid, GID: gid, Xattrs: map[string][]byte{"user.unrelated": []byte("root")}}
	updates := []struct{ name, text string }{
		{"absent", ""}, {"invalid", "!#acl broken\n"}, {"empty", "!#acl 1\n"}, {"empty-flags", "!#acl 1 no_inherit\n"},
		{"one", "!#acl 1\nuser:11234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n"},
		{"max", "!#acl 1 no_inherit\n" + strings.Repeat("user:11234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n", 128)},
	}
	var cases []Case
	var group uint64
	for i, p := range imagesecurity.Profiles() {
		for _, update := range updates {
			for _, kind := range []string{"file", "directory", "symlink", "hardlink"} {
				name := p.Name + "-" + update.name + "-" + kind
				mode := os.FileMode(0755)
				if i%3 == 0 {
					mode = 0
				}
				if i%3 == 1 {
					mode |= os.ModeSetuid | os.ModeSetgid | os.ModeSticky
				}
				e := &apfswrite.Entry{Name: name, Mode: mode, ModeExplicit: true, UID: uid, GID: gid, Data: []byte("payload"), Xattrs: map[string][]byte{"user.unrelated": []byte("retained")}}
				if p.Data != nil {
					e.Xattrs[hostdata.SecurityName] = append([]byte{}, p.Data...)
				}
				c := Case{Name: name, Target: name, Text: []byte(update.text)}
				switch kind {
				case "directory":
					e.Mode |= os.ModeDir
					e.Data = nil
				case "symlink":
					e.Mode |= os.ModeSymlink
					e.Data = []byte("missing-target")
				case "hardlink":
					group++
					e.LinkGroup = group
					e.Name += "-a"
					alias := *e
					alias.Name = name + "-b"
					root.Children = append(root.Children, &alias)
					c.Target = alias.Name
					c.Aliases = []string{e.Name}
				}
				root.Children = append(root.Children, e)
				cases = append(cases, c)
			}
		}
	}
	root.Children = append(root.Children, &apfswrite.Entry{Name: "implicit-dir", UID: uid, GID: gid, LinkGroup: 1, Children: []*apfswrite.Entry{{Name: "child", Data: []byte("nested")}}})
	cases = append(cases, Case{Name: "implicit-dir", Target: "implicit-dir", Text: []byte(updates[4].text)})
	cases = append(cases, Case{Name: "root", Target: ".", Text: []byte(updates[4].text)})
	zero := &apfswrite.Entry{Mode: os.ModeDir, ModeExplicit: true, UID: uid, GID: gid}
	return []Tree{{Name: "entries", Root: root, Cases: cases}, {Name: "root-zero", Root: zero, Cases: []Case{{Name: "root-zero", Target: ".", Text: []byte(updates[3].text)}}}}
}

func Update(text []byte) (appledouble.ACLUpdate, error) {
	return (&appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: text}}}).ACLUpdate(nil)
}

func ApplyAPFS(root *apfswrite.Entry, c Case) (aclmeta.ACLRestoreResult, error) {
	target := root
	if c.Target != "." {
		target = nil
		for _, child := range root.Children {
			if child.Name == c.Target {
				target = child
			}
		}
	}
	if target == nil {
		return aclmeta.ACLRestoreResult{}, fmt.Errorf("missing target %s", c.Target)
	}
	update, err := Update(c.Text)
	if err != nil {
		return aclmeta.ACLRestoreResult{}, err
	}
	return root.RestoreACL(target, update)
}
func ApplyHFS(root *hfsplus.Entry, c Case) (aclmeta.ACLRestoreResult, error) {
	target := root
	if c.Target != "." {
		target = nil
		for _, child := range root.Children {
			if child.Name == c.Target {
				target = child
			}
		}
	}
	if target == nil {
		return aclmeta.ACLRestoreResult{}, fmt.Errorf("missing target %s", c.Target)
	}
	update, err := Update(c.Text)
	if err != nil {
		return aclmeta.ACLRestoreResult{}, err
	}
	return root.RestoreACL(target, update)
}
