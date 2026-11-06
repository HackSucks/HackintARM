package hfsplus

import (
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// FileTimes reads catalog timestamps in UTC, resolving hard links but never
// following the final symlink. HFS stores whole seconds since 1904. Raw catalog
// dates are returned; this does not apply a host driver's sentinel conversion.
func (v *Volume) FileTimes(name string) (hostdata.FileTimes, error) {
	if v == nil || v.root == nil {
		return hostdata.FileTimes{}, &fs.PathError{Op: "timestamps", Path: name, Err: fs.ErrInvalid}
	}
	entry, err := v.entryByFSName("timestamps", name)
	if err != nil {
		return hostdata.FileTimes{}, err
	}
	var values [4]hfsTime
	if entry.isDir {
		s := entry.folder
		values = [4]hfsTime{s.CreateDate, s.ContentModDate, s.AttributeModDate, s.AccessDate}
	} else {
		s := entry.file
		values = [4]hfsTime{s.CreateDate, s.ContentModDate, s.AttributeModDate, s.AccessDate}
	}
	return hostdata.FileTimes{Birth: values[0].Time(), Modify: values[1].Time(), Change: values[2].Time(), Access: values[3].Time()}, nil
}
