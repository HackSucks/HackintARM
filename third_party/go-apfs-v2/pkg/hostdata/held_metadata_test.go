package hostdata

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

func logicalMetadataFixture(t *testing.T) *LogicalMetadata {
	t.Helper()
	u, g, m := uint32(501), uint32(20), uint32(0100644)
	x, err := NewLogicalMetadata(MetadataState{Security: SecurityCopySource{UID: u, GID: g, Mode: m, Properties: aclmeta.DarwinChmodProperties{UID: &u, GID: &g, Mode: &m}}, Stat: StatCopySource{UID: u, GID: g, Mode: m}})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestLogicalMetadata(t *testing.T) {
	x := logicalMetadataFixture(t)
	if _, err := NewHeldMetadata(nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	state := x.Snapshot()
	state.Stat.Mode++
	if _, err := NewLogicalMetadata(state); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	state = x.Snapshot()
	state.Security.Properties.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{}, NoACLFlags: [4]byte{1}}
	if _, err := NewLogicalMetadata(state); err == nil {
		t.Fatal("invalid security accepted")
	}
	before := x.Snapshot()
	*before.Security.Properties.UID = 999
	s, _ := x.CaptureSecurity()
	if s.UID != 501 || *s.Properties.UID != 501 {
		t.Fatal(s)
	}
	if err := x.SetACL(&appledouble.ACL{}); err != nil {
		t.Fatal(err)
	}
	acl, err := x.CaptureDestinationACL()
	if err != nil || acl == nil {
		t.Fatal(acl, err)
	}
	a, err := x.CaptureACL()
	if err != nil {
		t.Fatal(err)
	}
	a.UID = 502
	a.GID = 21
	a.Mode = 0600
	if err = x.WriteACL(a); err != nil {
		t.Fatal(err)
	}
	if err = x.WriteACL(aclmeta.ACLMetadata{}); err == nil {
		t.Fatal("nil ACL metadata")
	}
	if err = x.SetACL(nil); err != nil {
		t.Fatal(err)
	}
	if err = x.SetACL(&appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}); err == nil {
		t.Fatal("overlarge ACL")
	}
	if err = x.Chmod(0750); err != nil {
		t.Fatal(err)
	}
	if err = x.Chown(503, 22); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(123, 456)
	if err = x.SetTimes(now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = x.Chflags(17); err != nil {
		t.Fatal(err)
	}
	if v, _ := x.ReadFlags(); v != 17 {
		t.Fatal(v)
	}
	if v, _ := x.CompareAndSwapFlags(18, 19); v != 17 {
		t.Fatal(v)
	}
	if v, _ := x.CompareAndSwapFlags(17, 20); v != 17 {
		t.Fatal(v)
	}
	stat, _ := x.CaptureStat()
	if stat.UID != 503 || stat.GID != 22 || stat.Mode != 0100750 || stat.Flags != 20 || !stat.Times.Modify.Equal(now) || !stat.Times.Access.Equal(now.Add(time.Second)) {
		t.Fatal(stat)
	}
	uuid := [16]byte{1}
	s.Properties.OwnerUUID = &uuid
	s.Properties.GroupUUID = &uuid
	s.Properties.RawSecurity = &appledouble.FileSecurity{}
	x.SourceCache = &s
	if err = x.ClearSourceSecurity(); err != nil || s.Properties.RawSecurity != nil || s.Properties.OwnerUUID != nil || s.Properties.GroupUUID != nil {
		t.Fatal(s, err)
	}
	h := &HeldMetadata{heldMetadataOperations: x, SourceCache: &s}
	if err = h.ClearSourceSecurity(); err != nil {
		t.Fatal(err)
	}
	cap, err := CaptureSecuritySource(h.SourceCapture())
	if err != nil || !cap.Completed {
		t.Fatal(cap, err)
	}
	prior := SecuritySourceStat{UID: 1}
	next, err := h.SourceCapture().ReadStat(prior)
	if err != nil || next.UID != 503 {
		t.Fatal(next, err)
	}
	clearMetadataSource(nil)
}

func TestMetadataArgumentValidation(t *testing.T) {
	x := logicalMetadataFixture(t)
	for _, a := range []aclmeta.DarwinChmodArguments{
		{SecurityArgument: aclmeta.DarwinSecurityNone, Security: []byte{}},
		{SecurityArgument: aclmeta.DarwinSecurityRemove, Security: []byte{1}},
		{SecurityArgument: aclmeta.DarwinSecurityRecord, Security: []byte{1}},
		{SecurityArgument: 4}, {Mode: -2}, {Mode: 65536},
	} {
		if err := x.WriteSecurity(a); err == nil {
			t.Fatal(a)
		}
	}
	raw, _ := (&appledouble.FileSecurity{Trailing: []byte{1}}).MarshalDarwinBinary()
	if err := x.WriteSecurity(aclmeta.DarwinChmodArguments{SecurityArgument: aclmeta.DarwinSecurityRecord, Security: raw}); err == nil {
		t.Fatal("trailing accepted")
	}
	uuid := [16]byte{4}
	source := SecurityCopySource{Properties: aclmeta.DarwinChmodProperties{OwnerUUID: &uuid, GroupUUID: &uuid}}
	a := metadataACL(source)
	if a.Security.OwnerUUID != uuid || a.Security.GroupUUID != uuid {
		t.Fatal(a)
	}
	before := x.Snapshot()
	if err := x.WriteSecurity(aclmeta.DarwinChmodArguments{UID: 0xffffff9b, GID: 0xffffff9b, Mode: -1}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, x.Snapshot()) {
		t.Fatal("omitted values changed state")
	}
}
