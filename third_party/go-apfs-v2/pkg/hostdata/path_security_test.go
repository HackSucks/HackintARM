package hostdata

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

func TestPreparePathSecurity(t *testing.T) {
	mode := uint32(0410)
	uid := uint32(51)
	uuid := [16]byte{3}
	original := aclmeta.DarwinChmodProperties{UID: &uid, Mode: &mode, OwnerUUID: &uuid, RawSecurity: &appledouble.FileSecurity{OwnerUUID: [16]byte{4}, ACL: &appledouble.ACL{Flags: 2, Entries: []appledouble.ACLEntry{{Flags: 2, Rights: 7}}}}}
	prepared, e := PreparePathSecurity(original, [16]byte{9})
	if e != nil || *prepared.Mode != 0610 || len(prepared.RawSecurity.ACL.Entries) != 2 || prepared.RawSecurity.ACL.Entries[0] != (appledouble.ACLEntry{Principal: [16]byte{9}, Flags: 1, Rights: 1053988}) || prepared.RawSecurity.ACL.Flags != 2 {
		t.Fatal(prepared, e)
	}
	*prepared.UID = 99
	*prepared.OwnerUUID = [16]byte{99}
	prepared.RawSecurity.ACL.Entries[1].Rights = 99
	if mode != 0410 || uid != 51 || uuid != [16]byte{3} || original.RawSecurity.ACL.Entries[0].Rights != 7 {
		t.Fatal("borrowed mutable security")
	}
	for _, count := range []int{-1, 0, 127, 128} {
		p := aclmeta.DarwinChmodProperties{}
		if count >= 0 {
			p.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, count)}}
		}
		r, e := PreparePathSecurity(p, [16]byte{})
		if count == 128 {
			if !errors.Is(e, appledouble.ErrFileSecurity) {
				t.Fatal(e)
			}
			continue
		}
		if e != nil || r.Mode != nil || (count < 0 && r.RawSecurity != nil) || (count >= 0 && len(r.RawSecurity.ACL.Entries) != count+1) {
			t.Fatal(count, r, e)
		}
	}
	if _, e := PreparePathSecurity(aclmeta.DarwinChmodProperties{RemoveACL: true}, [16]byte{}); !errors.Is(e, appledouble.ErrFileSecurity) {
		t.Fatal(e)
	}
}

type pathResetModel struct {
	metadata              aclmeta.ACLMetadata
	capture, write, chmod error
	operations            []string
	written               *aclmeta.ACLMetadata
	mode                  uint16
}

func (m *pathResetModel) CaptureACL() (aclmeta.ACLMetadata, error) {
	m.operations = append(m.operations, "capture")
	return m.metadata, m.capture
}
func (m *pathResetModel) WriteACL(v aclmeta.ACLMetadata) error {
	m.operations = append(m.operations, "write")
	m.written = &v
	return m.write
}
func (m *pathResetModel) Chmod(mode uint16) error {
	m.operations = append(m.operations, "chmod")
	m.mode = mode
	return m.chmod
}
func TestResetPathSecurity(t *testing.T) {
	failure := errors.New("write refused")
	for _, flags := range []uint32{1, 1 | 16, 1 | 496, 2} {
		for _, rights := range []uint32{TemporaryWriteRights, TemporaryWriteRights | 2} {
			for _, matches := range []bool{false, true} {
				principal := [16]byte{1}
				if !matches {
					principal = [16]byte{2}
				}
				m := &pathResetModel{metadata: aclmeta.ACLMetadata{Mode: 0100600, UID: 51, GID: 20, Security: &appledouble.FileSecurity{OwnerUUID: [16]byte{3}, ACL: &appledouble.ACL{Flags: 4, Entries: []appledouble.ACLEntry{{Principal: principal, Flags: flags, Rights: rights}, {Principal: [16]byte{1}, Flags: 1, Rights: TemporaryWriteRights}}}}}}
				r, e := ResetPathSecurity(m, 0100440, [16]byte{1})
				matched := flags&0xf == 1 && rights == TemporaryWriteRights && matches
				if e != nil || r.Removed != matched || r.ModeRestored != matched {
					t.Fatal(r, e)
				}
				if !matched {
					if m.written != nil {
						t.Fatal("removed wrong ACE")
					}
					continue
				}
				if m.written.Mode != 0440 || len(m.written.Security.ACL.Entries) != 1 || m.written.UID != 51 || m.written.GID != 20 || m.written.Security.OwnerUUID != [16]byte{3} || m.written.Security.ACL.Flags != 4 {
					t.Fatal(m.written)
				}
				m.written.Security.ACL.Entries[0].Rights = 0
				if m.metadata.Security.ACL.Entries[1].Rights != TemporaryWriteRights {
					t.Fatal("borrowed snapshot")
				}
			}
		}
	}
	for _, tc := range []struct {
		name                  string
		capture, write, chmod error
		security              *appledouble.FileSecurity
		want                  []string
	}{
		{"absent", nil, nil, nil, &appledouble.FileSecurity{}, []string{"capture"}},
		{"empty", nil, nil, nil, &appledouble.FileSecurity{ACL: &appledouble.ACL{}}, []string{"capture"}},
		{"malformed", nil, nil, nil, nil, []string{"capture"}},
		{"stat-refused", os.ErrPermission, nil, nil, nil, []string{"capture"}},
		{"allocation", ErrFilesecAllocation, nil, nil, nil, []string{"capture", "chmod"}},
		{"unsupported", errors.ErrUnsupported, nil, nil, nil, []string{"capture", "chmod"}},
		{"source-unsupported", ErrSecuritySourceNotSupported, nil, nil, nil, []string{"capture", "chmod"}},
		{"unsupported-fallback-failed", errors.ErrUnsupported, nil, os.ErrPermission, nil, []string{"capture", "chmod"}},
		{"write-failed", nil, failure, nil, &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: TemporaryWriteRights}}}}, []string{"capture", "write", "chmod"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &pathResetModel{capture: tc.capture, write: tc.write, chmod: tc.chmod, metadata: aclmeta.ACLMetadata{Security: tc.security}}
			r, e := ResetPathSecurity(m, 0100440, [16]byte{1})
			if !reflect.DeepEqual(m.operations, tc.want) {
				t.Fatal(m.operations, tc.want)
			}
			for _, cause := range []error{tc.capture, tc.write, tc.chmod} {
				if cause != nil && !errors.Is(e, cause) {
					t.Fatal("lost error", cause, e)
				}
			}
			if len(tc.want) > 1 && (m.mode != 0440 || r.ModeRestored != (tc.chmod == nil)) {
				t.Fatal(m.mode, r)
			}
			if tc.name == "malformed" && !errors.Is(e, appledouble.ErrFileSecurity) {
				t.Fatal(e)
			}
		})
	}
	if _, e := ResetPathSecurity(nil, 0, [16]byte{}); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
}
