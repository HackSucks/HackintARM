// Package imagestat supplies image stat-restoration qualification fixtures.
package imagestat

import (
	"fmt"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/statcopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func Models() []statcopy.Case {
	var result []statcopy.Case
	for _, flags := range []uint32{0, 1, 2, 4, 0x40, 0x180080, 0x20, 0x22} {
		for _, options := range []int{0, 2, 4, 8} {
			target := uint32(0x40)
			if flags&0x20 != 0 {
				target |= 0x20
			}
			result = append(result, statcopy.Case{Name: fmt.Sprintf("%x-%d", flags, options), SourceFlags: flags, TargetFlags: target, Options: options})
		}
	}
	return result
}
func InitialTimes() hostdata.FileTimes {
	return hostdata.FileTimes{Birth: time.Unix(1400000000, 123456789), Modify: time.Unix(1550000000, 111111111), Change: time.Unix(1700000000, 222222222), Access: time.Unix(1450000000, 333333333)}
}

// Build uses native model requests as the independent expected values. It stages
// the real writer API separately for each format. Aliases are changed by one call.
func Build(models []statcopy.Case, hfs bool) (*apfswrite.Entry, *hfsplus.Entry, []imagesecurity.Case, error) {
	initial := InitialTimes()
	flags := uint32(0x40)
	root := &apfswrite.Entry{Mode: os.ModeDir | 0755, UID: 501, GID: 20, Times: &initial, BSDFlags: &flags, Xattrs: map[string][]byte{"org.example.keep": []byte("kept")}}
	type target struct {
		name, kind string
		index      int
		model      statcopy.Case
	}
	targets := []target{{".", "directory", -1, models[0]}}
	for i, tc := range models {
		for _, kind := range []string{"file", "directory", "symlink", "hard-a", "hard-b"} {
			if tc.SourceFlags&0x20 != 0 && (kind == "directory" || kind == "symlink") {
				continue
			}
			times, flags := initial, tc.TargetFlags
			e := &apfswrite.Entry{Name: tc.Name + "-" + kind, Mode: 0644, UID: 501, GID: 20, Times: &times, BSDFlags: &flags, Data: []byte("payload"), Xattrs: map[string][]byte{"org.example.keep": []byte("kept")}}
			switch kind {
			case "directory":
				e.Mode = os.ModeDir | 0755
				e.Data = nil
			case "symlink":
				e.Mode = os.ModeSymlink | 0755
				e.Data = []byte("target")
			case "hard-a", "hard-b":
				e.LinkGroup = uint64(i + 1)
			}
			if flags&0x20 != 0 {
				compressed, _ := imagesecurity.FlagTree()
				e.Xattrs["com.apple.decmpfs"] = compressed.Children[len(compressed.Children)-1].Xattrs["com.apple.decmpfs"]
				e.Data = nil
			}
			targets = append(targets, target{e.Name, kind, len(root.Children), tc})
			root.Children = append(root.Children, e)
		}
	}
	hroot := imagesecurity.HFSTree(root)
	var cases []imagesecurity.Case
	for _, t := range targets {
		if t.kind != "hard-b" {
			var result hostdata.ImageStatCopyResult
			var err error
			if hfs {
				dst := hroot
				if t.index >= 0 {
					dst = hroot.Children[t.index]
				}
				result, err = hroot.CopyStat(dst, t.model.Native.Source.Go(), statcopy.Options(t.model.Options))
			} else {
				dst := root
				if t.index >= 0 {
					dst = root.Children[t.index]
				}
				result, err = root.CopyStat(dst, t.model.Native.Source.Go(), statcopy.Options(t.model.Options))
			}
			if err != nil || !result.Applied || len(result.Execution.Failures) != 0 {
				return nil, nil, nil, fmt.Errorf("%s: %+v %v", t.name, result, err)
			}
		}
		wantTimes := [4]int64{initial.Birth.UnixNano(), initial.Modify.UnixNano(), initial.Change.UnixNano(), initial.Access.UnixNano()}
		uid, gid, mode, flags := uint32(501), uint32(20), uint16(0), uint32(0)
		for _, event := range t.model.Native.Events {
			if event.Code != 0 {
				return nil, nil, nil, fmt.Errorf("failed oracle operation")
			}
			switch event.Operation {
			case "times":
				wantTimes[1] = event.Times[0]*1e9 + event.Times[1]
				wantTimes[3] = event.Times[2]*1e9 + event.Times[3]
			case "ownership":
				uid, gid = event.UID, event.GID
			case "mode":
				mode = uint16(event.Mode)
			case "compare-flags", "flags":
				flags = event.Flags
			}
		}
		switch t.kind {
		case "directory":
			mode |= 040000
		case "symlink":
			mode |= 0120000
		default:
			mode |= 0100000
		}
		cases = append(cases, imagesecurity.Case{Name: t.name, Profile: "stat", Kind: t.kind, UID: uid, GID: gid, Mode: mode, Flags: &flags, Times: &wantTimes, Disposition: hostdata.SecurityRecordAbsent})
	}
	return root, hroot, cases, nil
}
