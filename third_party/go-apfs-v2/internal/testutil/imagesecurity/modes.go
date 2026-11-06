package imagesecurity

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type ModeTree struct {
	Name  string
	Root  *apfswrite.Entry
	Cases []Case
}

// Modes covers each special-bit combination, zero and ordinary permissions,
// legacy defaults, shared hard-link inodes and volume roots. Expected modes are
// numeric fixtures, not produced by the production conversion being tested.
func Modes(uid, gid uint32) []ModeTree {
	tree := &apfswrite.Entry{Mode: os.ModeDir | 0755, UID: uid, GID: gid}
	cases := []Case{{Name: ".", Kind: "directory", Profile: "parent", UID: uid, GID: gid, Mode: 040755}}
	var group uint64
	for _, profile := range []struct {
		name     string
		perm     uint16
		explicit bool
	}{
		{"zero", 0, true}, {"owner", 0600, true}, {"all", 0777, true}, {"default", 0, false},
	} {
		for special := uint16(0); special < 8; special++ {
			group++
			for _, kind := range []string{"file", "directory", "symlink", "hard-a", "hard-b"} {
				name := fmt.Sprintf("%s-%d-%s", profile.name, special, kind)
				mode := os.FileMode(profile.perm)
				if special&4 != 0 {
					mode |= os.ModeSetuid
				}
				if special&2 != 0 {
					mode |= os.ModeSetgid
				}
				if special&1 != 0 {
					mode |= os.ModeSticky
				}
				raw := uint16(0100000) | profile.perm | special<<9
				e := &apfswrite.Entry{Name: name, UID: uid, GID: gid, Mode: mode, ModeExplicit: profile.explicit, Data: []byte("payload"), Xattrs: map[string][]byte{"user.mode": []byte("retained")}}
				switch kind {
				case "directory":
					e.Mode |= os.ModeDir
					e.Data = nil
					raw = raw&07777 | 040000
				case "symlink":
					e.Mode |= os.ModeSymlink
					e.Data = []byte("missing-target")
					raw = raw&07777 | 0120000
				case "hard-a", "hard-b":
					e.LinkGroup = group
				}
				if !profile.explicit {
					if kind == "directory" || kind == "symlink" {
						raw |= 0755
					} else {
						raw |= 0644
					}
				}
				tree.Children = append(tree.Children, e)
				cases = append(cases, Case{Name: name, Profile: profile.name, Kind: kind, UID: uid, GID: gid, Mode: raw, Disposition: hostdata.SecurityRecordAbsent})
			}
		}
	}
	result := []ModeTree{{"entries", tree, cases}}
	for _, root := range []struct {
		name string
		mode os.FileMode
		raw  uint16
	}{
		{"root-zero", 0, 040000},
		{"root-special-zero", os.ModeDir | os.ModeSetuid | os.ModeSetgid | os.ModeSticky, 047000},
		{"root-special", os.ModeDir | os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0755, 047755},
	} {
		e := &apfswrite.Entry{Mode: root.mode, ModeExplicit: true, UID: uid, GID: gid}
		result = append(result, ModeTree{root.name, e, []Case{{Name: ".", Kind: "directory", Profile: root.name, UID: uid, GID: gid, Mode: root.raw}}})
	}
	return result
}
