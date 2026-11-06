package hfsplus

import (
	"errors"
	"io/fs"
	"testing"
)

func TestImageTimesMetadataOnly(t *testing.T) {
	file := &entry{name: "compressed", file: &HFSPlusCatalogFile{FileID: 16, BSDInfo: BSDInfo{OwnerFlags: ufCompressed}, CreateDate: 1, ContentModDate: 2, AttributeModDate: 3, AccessDate: 4}}
	v := &Volume{root: &entry{isDir: true, folder: &HFSPlusCatalogFolder{}, children: []*entry{file}}}
	got, err := v.FileTimes("compressed")
	if err != nil {
		t.Fatal(err)
	}
	if got.Birth != hfsTime(1).Time() || got.Modify != hfsTime(2).Time() || got.Change != hfsTime(3).Time() || got.Access != hfsTime(4).Time() {
		t.Fatal(got)
	}
	if v.attributes != nil || v.attrNames != nil {
		t.Fatal("timestamp capture loaded unrelated compression attributes")
	}
	// Control: the general Stat path does inspect compression metadata to compute size.
	if _, err = v.Stat("compressed"); err != nil || v.attributes == nil {
		t.Fatal("missing compression control", err)
	}
	if _, err = (&Volume{}).FileTimes("."); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}
