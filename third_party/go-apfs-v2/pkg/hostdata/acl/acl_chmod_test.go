package acl

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestNativeDarwinChmodRequests(t *testing.T) {
	f, e := os.Open("../../../testdata/appledouble/native/acl-chmod.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct {
		HelperSHA256, ParentHelperSHA256, LibcSHA256, XNUSHA256 string
		Conversions                                             []struct {
			Name    string
			Input   attributeMetadata
			Request DarwinChmodRequest
		}
		Applications []struct {
			Name, Kind              string
			Initial                 int
			Mode, Flags             uint32
			Text                    []byte
			Before                  attributeMetadata
			Response, AfterResponse []byte
			Request                 *DarwinChmodRequest
			Native                  attributeResult
		}
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if len(corpus.Conversions) != 84 || len(corpus.Applications) != 192 || corpus.LibcSHA256 != "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff" || corpus.XNUSHA256 != "b30d68fb85f34b864b5e71e3127541c2674e0fb52e59d6ee072c8b0ecbb46a4f" {
		t.Fatal("chmod corpus provenance")
	}
	for path, want := range map[string]string{"acl-chmod.c": corpus.HelperSHA256, "filesec.c": corpus.ParentHelperSHA256} {
		b, e := os.ReadFile("../../../testdata/appledouble/native/" + path)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("helper provenance", path)
		}
	}
	for _, tc := range corpus.Conversions {
		t.Run(tc.Name, func(t *testing.T) {
			b, e := hex.DecodeString(tc.Input.Security)
			if e != nil {
				t.Fatal(e)
			}
			sec, e := appledouble.ParseDarwinFileSecurity(b)
			if e != nil {
				t.Fatal(e)
			}
			m := ACLMetadata{Security: sec, UID: tc.Input.UID, GID: tc.Input.GID, Mode: tc.Input.Mode}
			r, e := m.DarwinChmodRequest()
			if e != nil || !reflect.DeepEqual(r, tc.Request) {
				t.Fatal("Libc argument construction differs", r, e)
			}
		})
	}
	attributes := readACLAttributesCorpus(t)
	noops, writes, refusals, fixedErrors, fixedFlags := 0, 0, 0, 0, 0
	for i, tc := range corpus.Applications {
		t.Run(tc.Name, func(t *testing.T) {
			a := attributes.Applications[i]
			if tc.Name != a.Name || tc.Kind != a.Kind || tc.Initial != a.Initial || tc.Mode != a.Mode || tc.Flags != a.Flags || !bytes.Equal(tc.Text, a.Text) || tc.Before != a.Before || !bytes.Equal(tc.Response, a.Response) || tc.Native != a.Reference || !bytes.Equal(tc.AfterResponse, a.ReferenceAfterResponse) {
				t.Fatal("copyfile control changed")
			}
			m := parseACLAttributes(t, tc.Response)
			checkACLAttributesSnapshot(t, m, tc.Before, true)
			file := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: tc.Text}}}
			u, e := file.ACLUpdate(nil)
			if e != nil {
				t.Fatal(e)
			}
			m.Security, e = u.FileSecurity(m.Security)
			if e != nil {
				t.Fatal(e)
			}
			var request *DarwinChmodRequest
			if m.Security != nil {
				r, e := m.DarwinChmodRequest()
				if e != nil {
					t.Fatal(e)
				}
				request = &r
			}
			if !reflect.DeepEqual(request, tc.Request) {
				t.Fatal("native extended chmod request differs")
			}
			if !tc.Native.IdentityUnchanged || tc.Before.Mode&07777 != tc.Mode || tc.Before.Flags != tc.Flags {
				t.Fatal("fixture setup/identity")
			}
			after := tc.Native.After
			if after.UID != tc.Before.UID || after.GID != tc.Before.GID || after.Mode != tc.Before.Mode || after.Flags != tc.Before.Flags {
				t.Fatal("ownership/mode/flags changed")
			}
			decoded := parseACLAttributes(t, tc.AfterResponse)
			checkACLAttributesSnapshot(t, decoded, after, true)
			switch {
			case request == nil:
				noops++
				if tc.Native.Code != 0 || !bytes.Equal(tc.Response, tc.AfterResponse) {
					t.Fatal("no-op changed metadata")
				}
			case tc.Native.Code == 0:
				writes++
				if !sameACLAttributes(m, decoded) {
					t.Fatal("accepted ACL differs")
				}
			default:
				refusals++
				if tc.Native.Code != -1 || tc.Native.Errno != 1 || after != tc.Before || !bytes.Equal(tc.Response, tc.AfterResponse) {
					t.Fatal("refusal lost error or changed metadata")
				}
			}
			if tc.Native.Errno != a.Native.Errno {
				fixedErrors++
				if tc.Native.Errno != 1 || a.Native.Errno != 0 {
					t.Fatal("unexpected corrected errno")
				}
			}
			if !bytes.Equal(tc.AfterResponse, a.AfterResponse) {
				fixedFlags++
				if tc.Initial != 0 || tc.Native.Errno != 1 || decoded.Security.ACL == nil || decoded.Security.ACL.Flags != 0x20000 {
					t.Fatal("no_inherit was not preserved")
				}
			}
		})
	}
	if noops != 96 || writes != 32 || refusals != 64 || fixedErrors != 16 || fixedFlags != 8 {
		t.Fatal("native outcome counts", noops, writes, refusals, fixedErrors, fixedFlags)
	}
}
func TestDarwinChmodRequestValidation(t *testing.T) {
	for _, security := range []*appledouble.FileSecurity{nil, {Trailing: []byte{1}}, {ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}}, {ACL: &appledouble.ACL{}, NoACLFlags: [4]byte{1}}} {
		r, e := (ACLMetadata{Security: security, UID: 501, GID: 20, Mode: 0644}).DarwinChmodRequest()
		if !errors.Is(e, appledouble.ErrFileSecurity) || !reflect.DeepEqual(r, DarwinChmodRequest{}) {
			t.Fatal("invalid request not rejected", e)
		}
	}
	m := ACLMetadata{Security: &appledouble.FileSecurity{OwnerUUID: [16]byte{17}, GroupUUID: [16]byte{34}, ACL: &appledouble.ACL{Flags: 0x80000000, Entries: []appledouble.ACLEntry{{Principal: [16]byte{51}, Flags: 0xffffffff, Rights: 0xffffffff}}}}, UID: 0, GID: 0xffffffff, Mode: 0xffff0000}
	before, e := m.Security.MarshalDarwinBinary()
	if e != nil {
		t.Fatal(e)
	}
	r, e := m.DarwinChmodRequest()
	if e != nil {
		t.Fatal(e)
	}
	second, e := m.DarwinChmodRequest()
	if e != nil {
		t.Fatal(e)
	}
	if r.UID != 0 || r.GID != 0xffffffff || r.Mode != 0 || !bytes.Equal(r.Security, before) {
		t.Fatal("fields/ownership lost")
	}
	clear(r.Security)
	after, e := m.Security.MarshalDarwinBinary()
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(after, before) || !bytes.Equal(second.Security, before) {
		t.Fatal("request storage borrowed")
	}
	m.Security.ACL.Entries[0].Rights = 0
	m.Security.OwnerUUID[0] = 0
	if !bytes.Equal(second.Security, before) {
		t.Fatal("request changed after input mutation")
	}
}
func FuzzDarwinChmodRequest(f *testing.F) {
	corpus := readACLAttributesCorpus(f)
	for _, tc := range corpus.Conversions {
		f.Add(tc.Input, tc.Expected.UID, tc.Expected.GID, tc.Expected.Mode)
	}
	f.Add([]byte{}, uint32(0), uint32(0), uint32(0))
	f.Fuzz(func(t *testing.T, b []byte, uid, gid, mode uint32) {
		if len(b) > 65536 {
			return
		}
		sec, e := appledouble.ParseDarwinFileSecurity(b)
		if e != nil {
			return
		}
		m := ACLMetadata{Security: sec, UID: uid, GID: gid, Mode: mode}
		r, e := m.DarwinChmodRequest()
		if len(sec.Trailing) > 0 {
			if !errors.Is(e, appledouble.ErrFileSecurity) || !reflect.DeepEqual(r, DarwinChmodRequest{}) {
				t.Fatal("trailing bytes accepted")
			}
			return
		}
		if e != nil || r.UID != uid || r.GID != gid || r.Mode != uint16(mode) || len(r.Security) > 3116 || !bytes.Equal(b, r.Security) {
			t.Fatal("argument loss or unbounded request", e)
		}
		next, e := m.DarwinChmodRequest()
		if e != nil {
			t.Fatal(e)
		}
		clear(r.Security)
		if !bytes.Equal(b, next.Security) {
			t.Fatal("aliased requests/input")
		}
	})
}
