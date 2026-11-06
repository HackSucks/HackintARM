package hfsplus

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestImageMetadataInvalidVolume(t *testing.T) {
	for _, v := range []*Volume{nil, {}, {root: &entry{isDir: true}}, {root: &entry{}}} {
		got, err := v.Metadata(".")
		var pe *fs.PathError
		if !errors.As(err, &pe) || pe.Op != "metadata" || !errors.Is(err, fs.ErrInvalid) || got != (hostdata.ImageMetadata{}) {
			t.Fatalf("%+v %v", got, err)
		}
	}
}

func TestImageMetadataDoesNotReadAttributes(t *testing.T) {
	file := &entry{name: "compressed", file: &HFSPlusCatalogFile{FileID: 16, BSDInfo: BSDInfo{OwnerID: 42, GroupID: 43, FileMode: 0100000, OwnerFlags: ufCompressed}, CreateDate: 1, ContentModDate: 2, AttributeModDate: 3, AccessDate: 4}}
	v := &Volume{root: &entry{isDir: true, folder: &HFSPlusCatalogFolder{}, children: []*entry{file}}}
	got, e := v.Metadata("compressed")
	if e != nil || got.UID != 42 || got.GID != 43 || got.Mode != 0100000 || got.LinkID != 16 || got.BSDFlags != uint32(ufCompressed) || got.Times.Birth != hfsTime(1).Time() {
		t.Fatalf("%+v %v", got, e)
	}
	if v.attributes != nil || v.attrNames != nil {
		t.Fatal("loaded unrelated attributes")
	}
}
