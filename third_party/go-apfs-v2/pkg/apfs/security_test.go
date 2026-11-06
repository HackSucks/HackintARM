package apfs

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type imageSecurityFault struct{ err error }

func (r imageSecurityFault) ReadAt([]byte, int64) (int, error) { return 0, r.err }

func TestImageSecurityErrorsAndStreams(t *testing.T) {
	var v *Volume
	for _, name := range []string{".", "", "../x"} {
		got, e := v.Security(name)
		var pe *fs.PathError
		if e == nil || !errors.As(e, &pe) || pe.Op != "security" || got.Source.Properties.UID != nil {
			t.Fatalf("invalid volume/path: %+v %v", got, e)
		}
	}
	inode := &Inode{OwnerIdentifier: 42, GroupIdentifier: 43, FileMode: 0100644}
	fe := &FileEntry{Inode: inode}
	if _, e := fe.security(); e == nil {
		t.Fatal("missing tree accepted")
	}
	record, e := (&appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 1}}}}).MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	attr := &AttributeValues{Name: []byte(hostdata.SecurityName), Flags: ExtendedAttributeFlagDataStream, ValueDataSize: uint64(len(record))}
	fe.ExtendedAttributes = []*AttributeValues{attr}
	if _, e = fe.security(); e == nil {
		t.Fatal("missing extents accepted")
	}
	attr.ValueDataFileExtents = []*FileExtent{{PhysicalBlockNumber: 1, DataSize: 4096}}
	if _, e = fe.security(); e == nil {
		t.Fatal("missing IO accepted")
	}
	fe.IOHandle = &IOHandle{BlockSize: 4096, BytesPerSector: 512}
	sentinel := errors.New("security stream read failed")
	fe.FileHandle = imageSecurityFault{sentinel}
	if _, e = fe.security(); !errors.Is(e, sentinel) {
		t.Fatalf("lost read failure: %v", e)
	}
	fe.FileHandle = bytes.NewReader(nil)
	if _, e = fe.security(); e == nil {
		t.Fatal("truncated stream accepted")
	}
	// A corrupt extent length must not cause an unbounded value allocation or
	// touch the inaccessible backing stream.
	attr.ValueDataSize = 1 << 40
	got, e := fe.security()
	if e != nil || got.Disposition != hostdata.SecurityRecordInvalid {
		t.Fatalf("extent bound: %+v %v", got, e)
	}
	attr.ValueDataSize = uint64(len(record))
	disk := make([]byte, 8192)
	copy(disk[4096:], record)
	fe.FileHandle = bytes.NewReader(disk)
	got, e = fe.security()
	if e != nil || got.Disposition != hostdata.SecurityRecordACL {
		t.Fatalf("valid stream: %+v %v", got, e)
	}
	fe.FileHandle = imageSecurityFault{io.ErrUnexpectedEOF}
	if _, e = fe.security(); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatalf("short stream: %v", e)
	}
}

func TestImageSecurityShortRead(t *testing.T) {
	attr := &ExtendedAttribute{DataStream: &DataStream{size: 68, readerAt: bytes.NewReader(make([]byte, 50))}}
	if _, e := imageSecurityValue(attr); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatalf("short read accepted: %v", e)
	}
}
