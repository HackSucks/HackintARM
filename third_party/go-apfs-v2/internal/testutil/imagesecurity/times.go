package imagesecurity

import (
	"fmt"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// TimeTree includes explicit epoch zero, legacy defaults, independent fields,
// sparse tree shapes and hard-link aliases. Actor IDs are fixed for image hashes.
func TimeTree(clamp bool) (*apfswrite.Entry, []Case) {
	base := time.Unix(1600000000, 123456789).UTC()
	distinct := hostdata.FileTimes{Birth: base.Add(-24 * time.Hour), Modify: base, Change: base.Add(time.Second), Access: base.Add(2 * time.Second)}
	root := &apfswrite.Entry{Mode: os.ModeDir | 0755, Times: &distinct, UID: 501, GID: 20}
	var cases []Case
	add := func(name, kind string, e *apfswrite.Entry) {
		e.Name = name
		e.UID, e.GID = 501, 20
		mode := uint16(0100644)
		if kind == "directory" {
			e.Mode = os.ModeDir | 0755
			mode = 040755
		} else if kind == "symlink" {
			e.Mode = os.ModeSymlink | 0755
			e.Data = []byte("target")
			mode = 0120755
		} else {
			e.Data = []byte("payload")
		}
		root.Children = append(root.Children, e)
		tc := Case{Name: name, Profile: "time", Kind: kind, UID: 501, GID: 20, Mode: mode, Disposition: hostdata.SecurityRecordAbsent}
		tc.Times = expectedTimes(e, clamp)
		cases = append(cases, tc)
	}
	cases = append(cases, Case{Name: ".", Profile: "time", Kind: "directory", UID: 501, GID: 20, Mode: 040755, Disposition: hostdata.SecurityRecordAbsent, Times: expectedTimes(root, clamp)})
	for i, profile := range []string{"distinct", "epoch", "legacy", "legacy-epoch", "future", "fractional", "hfs-last-second"} {
		for _, kind := range []string{"file", "directory", "symlink", "hard-a", "hard-b"} {
			times := distinct
			e := &apfswrite.Entry{Times: &times}
			switch profile {
			case "epoch":
				times = hostdata.FileTimes{Birth: time.Unix(0, 0), Modify: time.Unix(0, 0), Change: time.Unix(0, 0), Access: time.Unix(0, 0)}
			case "legacy":
				e.Times = nil
				e.ModTime = base
			case "legacy-epoch":
				e.Times = nil
				e.ModTime = time.Unix(0, 0)
			case "future":
				times.Modify = base.AddDate(10, 0, 0)
				times.Access = times.Modify.Add(time.Hour)
			case "fractional":
				times = hostdata.FileTimes{Birth: time.Unix(10, 1), Modify: time.Unix(20, 999999999), Change: time.Unix(30, 500000001), Access: time.Unix(40, 765432109)}
			case "hfs-last-second":
				last := time.Unix(2212122495, 999999999)
				times = hostdata.FileTimes{Birth: last, Modify: last, Change: last, Access: last}
			}
			if kind == "hard-a" || kind == "hard-b" {
				e.LinkGroup = uint64(i + 1)
			}
			add(fmt.Sprintf("%s-%s", profile, kind), kind, e)
		}
	}
	// Nested metadata must survive a snapshot too.
	nested := &apfswrite.Entry{Name: "child", Data: []byte("payload"), Times: &distinct, UID: 501, GID: 20}
	root.Children[1].Children = []*apfswrite.Entry{nested}
	cases = append(cases, Case{Name: root.Children[1].Name + "/child", Profile: "time", Kind: "file", UID: 501, GID: 20, Mode: 0100644, Disposition: hostdata.SecurityRecordAbsent, Times: expectedTimes(nested, clamp)})
	return root, cases
}
func expectedTimes(e *apfswrite.Entry, clamp bool) *[4]int64 {
	stamp := e.ModTime
	if stamp.IsZero() {
		stamp = apfswrite.DefaultTime
	}
	if clamp && stamp.After(apfswrite.DefaultTime) {
		stamp = apfswrite.DefaultTime
	}
	values := [4]time.Time{stamp, stamp, stamp, stamp}
	if e.Times != nil {
		values = [4]time.Time{e.Times.Birth, e.Times.Modify, e.Times.Change, e.Times.Access}
		if clamp && values[1].After(apfswrite.DefaultTime) {
			values[1] = apfswrite.DefaultTime
		}
	}
	result := [4]int64{}
	for i, v := range values {
		result[i] = v.UnixNano()
	}
	return &result
}
