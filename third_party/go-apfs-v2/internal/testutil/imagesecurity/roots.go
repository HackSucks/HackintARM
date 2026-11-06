package imagesecurity

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// RootTree exercises special inode metadata separately from user inode counts.
type RootTree struct {
	Name      string
	Root      *apfswrite.Entry
	Case      Case
	Snapshots []apfswrite.SnapshotSpec
}

func Roots(uid, gid uint32) []RootTree {
	var result []RootTree
	for _, name := range []string{"default", "owner-mode", "inline-acl", "empty-acl", "max-acl", "streamed-empty-tree", "streamed-with-children", "empty-fork", "fork", "wide-snapshot", "special-mode", "zero-permissions", "epoch"} {
		root := &apfswrite.Entry{Mode: os.ModeDir | 0755, UID: uid, GID: gid, ModTime: time.Unix(1600000000, 123456789), Xattrs: map[string][]byte{"user.empty": {}, "user.root": []byte("root-metadata")}}
		tc := Case{Name: ".", Profile: name, Kind: "directory", UID: uid, GID: gid, Mode: 040755, Disposition: hostdata.SecurityRecordAbsent}
		var snaps []apfswrite.SnapshotSpec
		switch name {
		case "zero-permissions":
			root.Mode = os.ModeDir
			root.Xattrs = nil
			tc.Mode = 040000
		case "epoch":
			root.ModTime = time.Unix(0, 0)
		case "default":
			root = &apfswrite.Entry{}
			tc.UID, tc.GID = 0, 0
		case "owner-mode":
			root.Mode = os.ModeDir | 0711
			tc.Mode = 040711
			root.UID, root.GID = 42, 43
			tc.UID, tc.GID = 42, 43
		case "inline-acl":
			root.Xattrs[hostdata.SecurityName] = Profiles()[7].Data
			tc.Disposition = hostdata.SecurityRecordACL
		case "empty-acl":
			root.Xattrs[hostdata.SecurityName] = Profiles()[5].Data
			tc.Disposition = hostdata.SecurityRecordEmpty
		case "max-acl":
			root.Xattrs[hostdata.SecurityName] = Profiles()[12].Data
			tc.Disposition = hostdata.SecurityRecordACL
		case "streamed-empty-tree", "streamed-with-children":
			root.Xattrs["user.large"] = bytes.Repeat([]byte{0x5a}, 32769)
			root.Xattrs[hostdata.SecurityName] = Profiles()[7].Data
			tc.Disposition = hostdata.SecurityRecordACL
			if name == "streamed-with-children" {
				root.Children = []*apfswrite.Entry{{Name: "a", Data: []byte("payload"), LinkGroup: 1}, {Name: "b", Data: []byte("payload"), LinkGroup: 1}, {Name: "dir", Mode: os.ModeDir | 0755}}
			}
		case "empty-fork":
			root.Xattrs["com.apple.ResourceFork"] = []byte{}
		case "fork":
			root.Xattrs["com.apple.ResourceFork"] = bytes.Repeat([]byte{0x6b}, 8193)
		case "wide-snapshot":
			for i := 0; i < 160; i++ {
				root.Xattrs[fmt.Sprintf("user.attr%03d", i)] = bytes.Repeat([]byte{byte(i)}, 128)
			}
			root.Xattrs["user.large"] = bytes.Repeat([]byte{0x77}, 16385)
			snaps = []apfswrite.SnapshotSpec{{Name: "root-snapshot"}}
		case "special-mode":
			root.Mode = os.ModeDir | 0755 | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
			tc.Mode = 047755
		}
		result = append(result, RootTree{Name: name, Root: root, Case: tc, Snapshots: snaps})
	}
	return result
}
