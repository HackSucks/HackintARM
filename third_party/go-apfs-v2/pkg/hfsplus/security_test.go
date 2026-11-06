package hfsplus

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type imageSecurityFault struct{ err error }

func (r imageSecurityFault) ReadAt([]byte, int64) (int, error) { return 0, r.err }

func TestImageSecurityErrorsAndForks(t *testing.T) {
	for _, v := range []*Volume{nil, {}, {root: &entry{isDir: true}}, {root: &entry{}}} {
		for _, name := range []string{".", "", "../x"} {
			got, e := v.Security(name)
			var pe *fs.PathError
			if e == nil || !errors.As(e, &pe) || pe.Op != "security" || !reflect.DeepEqual(got, hostdata.ImageSecurity{}) {
				t.Fatalf("invalid volume/path: %+v %v", got, e)
			}
		}
	}
	v := &Volume{root: &entry{isDir: true, folder: &HFSPlusCatalogFolder{FolderID: 2, BSDInfo: BSDInfo{OwnerID: 42, GroupID: 43, FileMode: 040755}}}, attributes: map[attrKey]*attrRecord{}}
	key := attrKey{fileID: 2, name: hostdata.SecurityName}
	v.attributes[key] = &attrRecord{}
	if _, e := v.Security("."); !errors.Is(e, fs.ErrInvalid) {
		t.Fatalf("unreadable record: %v", e)
	}
	record, e := (&appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 1}}}}).MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	v.attributes[key] = &attrRecord{hasFork: true, fork: ForkData{LogicalSize: uint64(len(record)), TotalBlocks: 1, Extents: ExtentRecord{{StartBlock: 1, BlockCount: 1}}}}
	v.blockSize = 512
	sentinel := errors.New("security fork read failed")
	v.dev = imageSecurityFault{sentinel}
	if _, e = v.Security("."); !errors.Is(e, sentinel) {
		t.Fatalf("lost fork read error: %v", e)
	}
	v.attributes[key].fork.LogicalSize = 1 << 40
	got, e := v.Security(".")
	if e != nil || got.Disposition != hostdata.SecurityRecordInvalid {
		t.Fatalf("extent bound: %+v %v", got, e)
	}
	v.attributes[key].fork.LogicalSize = uint64(len(record))
	disk := make([]byte, 1024)
	copy(disk[512:], record)
	v.dev = bytes.NewReader(disk)
	got, e = v.Security(".")
	if e != nil || got.Disposition != hostdata.SecurityRecordACL {
		t.Fatalf("valid fork: %+v %v", got, e)
	}
	v.dev = bytes.NewReader(nil)
	if _, e = v.Security("."); !errors.Is(e, io.EOF) && !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatalf("short fork: %v", e)
	}
}

func TestImageSecurityFailedAttributeLoadRetries(t *testing.T) {
	const id = CatalogNodeID(2)
	recs := []btRecord{{key: encodeAttrKey(id, "a", 0), payload: attrInlineRecord([]byte("ok"))}, {key: encodeAttrKey(id, hostdata.SecurityName, 0), payload: []byte{0, 0, 0, 0x10}}}
	v := attrVolume(t, 512, recs, nil)
	v.root = &entry{isDir: true, folder: &HFSPlusCatalogFolder{FolderID: id}}
	for i := 0; i < 2; i++ {
		if _, e := v.Security("."); e == nil || v.attributes != nil || v.attrNames != nil {
			t.Fatalf("partial failed cache retained, attempt %d: %v", i, e)
		}
	}
	good := attrVolume(t, 512, []btRecord{{key: encodeAttrKey(id, hostdata.SecurityName, 0), payload: attrInlineRecord([]byte{})}}, nil)
	v.dev, v.hdr = good.dev, good.hdr
	got, e := v.Security(".")
	if e != nil || got.Disposition != hostdata.SecurityRecordInvalid {
		t.Fatalf("retry after recovery: %+v %v", got, e)
	}
	v.attributes, v.attrNames = nil, nil
	sentinel := errors.New("attribute tree read failed")
	v.dev = imageSecurityFault{sentinel}
	for i := 0; i < 2; i++ {
		if _, e := v.Security("."); !errors.Is(e, sentinel) || v.attributes != nil || v.attrNames != nil {
			t.Fatalf("tree error swallowed: %v", e)
		}
	}
}

func TestImageSecurityPrivateDirectoryOrdering(t *testing.T) {
	// NUL is not a POSIX filename character, but it occurs in the four-NUL
	// on-disk hard-link directory. Native FastUnicodeCompare maps it to FFFF.
	for _, name := range []string{"", "a", "z", "\ufffe"} {
		if compareCatalogKeysFolded(encodeCatalogKey(2, name), encodeCatalogKey(2, metadataDirName)) >= 0 {
			t.Fatalf("private directory ordered before %q", name)
		}
	}
	if compareCatalogKeysFolded(encodeCatalogKey(2, "\x00"), encodeCatalogKey(2, "\uffff")) != 0 {
		t.Fatal("NUL fold")
	}
	if compareCatalogKeys(encodeCatalogKey(2, metadataDirName), encodeCatalogKey(2, "a")) >= 0 {
		t.Fatal("HFSX binary order changed")
	}
}
