package imagesecurity

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// FlagTree keeps fixed identities for byte-identical foreign-host output. Each
// flag has files, directories, final symlinks and two names for a shared inode.
func FlagTree() (*apfswrite.Entry, []Case) {
	rootFlags := uint32(0x8049)
	root := &apfswrite.Entry{Mode: os.ModeDir | 0755, UID: 501, GID: 20, BSDFlags: &rootFlags}
	cases := []Case{{Name: ".", Profile: "flags", Kind: "directory", UID: 501, GID: 20, Mode: 040755, Flags: &rootFlags, Disposition: hostdata.SecurityRecordAbsent}}
	for i, flags := range []uint32{0, 1, 2, 4, 8, 0x8000, 0x40, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x18800f} {
		for _, kind := range []string{"file", "directory", "symlink", "hard-a", "hard-b"} {
			e := &apfswrite.Entry{Name: fmt.Sprintf("%x-%s", flags, kind), UID: 501, GID: 20, Mode: 0644, Data: []byte("payload"), BSDFlags: &flags}
			mode := uint16(0100644)
			switch kind {
			case "directory":
				e.Mode = os.ModeDir | 0755
				e.Data = nil
				mode = 040755
			case "symlink":
				e.Mode = os.ModeSymlink | 0755
				e.Data = []byte("target")
				mode = 0120755
			case "hard-a", "hard-b":
				e.LinkGroup = uint64(i + 1)
			}
			root.Children = append(root.Children, e)
			cases = append(cases, Case{Name: e.Name, Profile: "flags", Kind: kind, UID: 501, GID: 20, Mode: mode, Flags: &flags, Disposition: hostdata.SecurityRecordAbsent})
		}
	}
	// Explicit and inferred compression must agree and both retain actual data.
	for _, explicit := range []bool{false, true} {
		name := fmt.Sprintf("compressed-%t", explicit)
		flags := uint32(0x20)
		data := make([]byte, 17)
		copy(data, "fpmc")
		binary.LittleEndian.PutUint32(data[4:], 3)
		binary.LittleEndian.PutUint64(data[8:], 7)
		data[16] = 0xff
		data = append(data, []byte("payload")...)
		e := &apfswrite.Entry{Name: name, UID: 501, GID: 20, Mode: 0644, Xattrs: map[string][]byte{"com.apple.decmpfs": data}}
		if explicit {
			e.BSDFlags = &flags
		}
		root.Children = append(root.Children, e)
		cases = append(cases, Case{Name: name, Profile: "flags", Kind: "file", UID: 501, GID: 20, Mode: 0100644, Flags: &flags, Disposition: hostdata.SecurityRecordAbsent})
	}
	childFlags := uint32(0x8001)
	root.Children[1].Children = []*apfswrite.Entry{{Name: "child", UID: 501, GID: 20, Mode: 0644, Data: []byte("payload"), BSDFlags: &childFlags}}
	cases = append(cases, Case{Name: root.Children[1].Name + "/child", Profile: "flags", Kind: "file", UID: 501, GID: 20, Mode: 0100644, Flags: &childFlags, Disposition: hostdata.SecurityRecordAbsent})
	return root, cases
}
