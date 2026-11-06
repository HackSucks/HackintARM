package hfsplus

import (
	"errors"
	"io/fs"
	"testing"
)

func TestImageFlagsMetadataOnly(t *testing.T) {
	file := &entry{name: "compressed", file: &HFSPlusCatalogFile{FileID: 16, BSDInfo: BSDInfo{FileMode: sIFREG | 0644, OwnerFlags: ufCompressed}}}
	v := &Volume{root: &entry{isDir: true, folder: &HFSPlusCatalogFolder{}, children: []*entry{file}}}
	got, err := v.BSDFlags("compressed")
	if err != nil || got != 0x20 {
		t.Fatal(got, err)
	}
	if v.attributes != nil || v.attrNames != nil {
		t.Fatal("flag read loaded compression metadata")
	}
	if _, err = v.Stat("compressed"); err != nil || v.attributes == nil {
		t.Fatal("missing control", err)
	}
	if _, err = (&Volume{}).BSDFlags("."); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}
