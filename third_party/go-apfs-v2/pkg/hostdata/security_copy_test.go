package hostdata_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

func TestNativeSecurityCopy(t *testing.T) {
	b, e := os.ReadFile("../../testdata/appledouble/native/security-copy.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var f securitycopy.Fixture
	if e = json.NewDecoder(z).Decode(&f); e != nil {
		t.Fatal(e)
	}
	helper, e := os.ReadFile("../../testdata/appledouble/native/security-copy.c")
	if e != nil {
		t.Fatal(e)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if f.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(helper)) || f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || f.LibcSHA256 != "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff" {
		t.Fatal("source/helper provenance")
	}
	if len(f.Models) != 2160 || len(f.Applications) != 216 {
		t.Fatalf("required corpus missing cases: %d/%d", len(f.Models), len(f.Applications))
	}
	for _, cases := range [][]securitycopy.Case{f.Models, f.Applications} {
		for _, tc := range cases {
			t.Run(tc.Name, func(t *testing.T) {
				result, _, err := securitycopy.Replay(tc)
				if err != nil {
					t.Fatal(err)
				}
				if tc.Kind != "" {
					n := tc.Native
					if !n.IdentityUnchanged || !n.PayloadUnchanged || n.Filesystem != "apfs" || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) {
						t.Fatal("native preservation")
					}
					if !result.Completed {
						t.Fatal("native stage completion")
					}
				}
			})
		}
	}
}

type copyBackend struct {
	capture  func() (*appledouble.ACL, error)
	security func(aclmeta.DarwinChmodArguments) error
	mode     func(uint16) error
	owner    func(uint32, uint32) error
	acl      func(*appledouble.ACL) error
}

func (b copyBackend) CaptureDestinationACL() (*appledouble.ACL, error)   { return b.capture() }
func (b copyBackend) WriteSecurity(v aclmeta.DarwinChmodArguments) error { return b.security(v) }
func (b copyBackend) Chmod(v uint16) error                               { return b.mode(v) }
func (b copyBackend) Chown(u, g uint32) error                            { return b.owner(u, g) }
func (b copyBackend) SetACL(v *appledouble.ACL) error                    { return b.acl(v) }

func TestSecurityCopyValidationAndOwnership(t *testing.T) {
	update := hostdata.SecurityCopyOptions{ACL: true, Stat: true}
	for _, tc := range []struct {
		name string
		p    aclmeta.DarwinChmodProperties
	}{
		{"removal", aclmeta.DarwinChmodProperties{RemoveACL: true}},
		{"trailing", aclmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{Trailing: []byte{1}}}},
		{"too-many", aclmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := hostdata.CopySecurity(hostdata.SecurityCopySource{Properties: tc.p}, update, copyBackend{})
			if !errors.Is(e, appledouble.ErrFileSecurity) || r.Completed || r.Writes != 0 {
				t.Fatalf("validation result %+v: %v", r, e)
			}
		})
	}
	if r, e := hostdata.CopySecurity(hostdata.SecurityCopySource{}, update, nil); !errors.Is(e, os.ErrInvalid) || r.Completed {
		t.Fatalf("nil backend: %+v %v", r, e)
	}
	if r, e := hostdata.CopySecurity(hostdata.SecurityCopySource{}, hostdata.SecurityCopyOptions{}, nil); e != nil || !r.Completed || r.Writes != 0 {
		t.Fatalf("noop: %+v %v", r, e)
	}
	captureErr := errors.New("capture failed")
	b := copyBackend{capture: func() (*appledouble.ACL, error) { return nil, captureErr }}
	if r, e := hostdata.CopySecurity(hostdata.SecurityCopySource{}, update, b); !errors.Is(e, captureErr) || r.Completed || r.Writes != 0 {
		t.Fatalf("capture error: %+v %v", r, e)
	}
	b.capture = func() (*appledouble.ACL, error) {
		return &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}, nil
	}
	if r, e := hostdata.CopySecurity(hostdata.SecurityCopySource{}, update, b); !errors.Is(e, appledouble.ErrACLCopy) || r.Completed || r.Writes != 0 {
		t.Fatalf("invalid destination: %+v %v", r, e)
	}
	uid, gid, mode := uint32(42), uint32(43), uint32(06755)
	owner, group := [16]byte{0x11}, [16]byte{0x22}
	acl := &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 1}}}
	source := hostdata.SecurityCopySource{UID: 44, GID: 45, Mode: 06711, Properties: aclmeta.DarwinChmodProperties{UID: &uid, GID: &gid, Mode: &mode, OwnerUUID: &owner, GroupUUID: &group, RawSecurity: &appledouble.FileSecurity{ACL: acl}}}
	destination := &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 17, Rights: 2}}}
	writeErr, modeErr, ownerErr, aclErr := errors.New("combined"), errors.New("mode"), errors.New("owner"), errors.New("acl")
	b = copyBackend{
		capture: func() (*appledouble.ACL, error) {
			uid, gid, mode = 99, 98, 0
			owner[0], group[0] = 3, 4
			acl.Entries[0].Rights = 99
			return destination, nil
		},
		security: func(a aclmeta.DarwinChmodArguments) error {
			if a.UID != 42 || a.GID != 43 || a.Mode != 06755 || a.SecurityArgument != aclmeta.DarwinSecurityRecord {
				t.Fatalf("frozen argument %+v", a)
			}
			clear(a.Security)
			destination.Entries[0].Rights = 100
			return writeErr
		},
		mode: func(m uint16) error {
			if m != 06711 {
				t.Fatalf("fallback stat mode %o", m)
			}
			return modeErr
		},
		owner: func(u, g uint32) error {
			if u != 44 || g != 45 {
				t.Fatalf("fallback stat IDs %d/%d", u, g)
			}
			return ownerErr
		},
		acl: func(a *appledouble.ACL) error {
			if len(a.Entries) != 2 || a.Entries[0].Rights != 1 || a.Entries[1].Rights != 2 {
				t.Fatalf("frozen fallback ACL %+v", a)
			}
			a.Entries[0].Rights = 101
			return aclErr
		},
	}
	r, e := hostdata.CopySecurity(source, update, b)
	if e != nil || !r.Completed || !r.Fallback || r.Writes != 4 || len(r.Failures) != 4 {
		t.Fatalf("fallback result %+v: %v", r, e)
	}
	for i, want := range []error{writeErr, modeErr, ownerErr, aclErr} {
		if !errors.Is(r.Failures[i].Err, want) {
			t.Fatal("lost error cause")
		}
	}
	p := r.Source.Properties
	if *p.UID != 42 || *p.GID != 43 || *p.Mode != 06755 || p.OwnerUUID[0] != 0x11 || p.GroupUUID[0] != 0x22 || p.RawSecurity.ACL.Entries[0].Rights != 1 || p.RawSecurity.ACL.Entries[1].Rights != 2 {
		t.Fatal("source cache aliased input or backend")
	}
	*p.UID = 200
	p.RawSecurity.ACL.Entries[0].Rights = 201
	if uid != 99 || acl.Entries[0].Rights != 99 || destination.Entries[0].Rights != 100 {
		t.Fatal("result aliases input")
	}
}

func FuzzSecurityCopy(f *testing.F) {
	for _, seed := range [][]byte{{0}, {1, 1, 1, 255}, {2, 4, 0, 0}, {3, 31, 5, 255}, {3, 0, 3, 1, 2, 3}, {1, 24, 2, 3, 4}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}
		u, g, m := uint32(data[0]), uint32(data[1]), uint32(data[2])<<12|uint32(data[3])
		p := aclmeta.DarwinChmodProperties{}
		if data[1]&1 != 0 {
			p.UID = &u
		}
		if data[1]&2 != 0 {
			p.GID = &g
		}
		if data[1]&4 != 0 {
			p.Mode = &m
		}
		if data[1]&8 != 0 {
			p.OwnerUUID = &[16]byte{data[0]}
		}
		if data[1]&16 != 0 {
			p.GroupUUID = &[16]byte{data[2]}
		}
		if len(data) > 4 {
			p.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{}}
			for _, v := range data[4:] {
				if len(p.RawSecurity.ACL.Entries) == 128 {
					break
				}
				p.RawSecurity.ACL.Entries = append(p.RawSecurity.ACL.Entries, appledouble.ACLEntry{Flags: uint32(v), Rights: uint32(v) << 24})
			}
		}
		before := securitycopy.PropertiesFromGo(p)
		failure := errors.New("write")
		calls := 0
		b := copyBackend{capture: func() (*appledouble.ACL, error) { return nil, nil }, security: func(a aclmeta.DarwinChmodArguments) error {
			calls++
			if a.SecurityArgument == aclmeta.DarwinSecurityRecord {
				if _, e := appledouble.ParseDarwinFileSecurity(a.Security); e != nil {
					t.Fatal(e)
				}
			}
			if data[3]&1 != 0 {
				return failure
			}
			return nil
		}, mode: func(uint16) error { calls++; return failure }, owner: func(uint32, uint32) error { calls++; return failure }, acl: func(a *appledouble.ACL) error {
			calls++
			if len(a.Entries) > 128 {
				t.Fatal("ACL bound")
			}
			return failure
		}}
		r, e := hostdata.CopySecurity(hostdata.SecurityCopySource{Properties: p, UID: u, GID: g, Mode: m}, securitycopy.Options(int(data[0]%4), int(data[2]%5)), b)
		if e != nil || !r.Completed || r.Writes != calls || calls > 4 || len(r.Failures) > calls || !reflect.DeepEqual(before, securitycopy.PropertiesFromGo(p)) {
			t.Fatalf("copy invariant %+v %v", r, e)
		}
	})
}

func TestSecurityCopyNOACLSource(t *testing.T) {
	source := hostdata.SecurityCopySource{Mode: 0644, Properties: aclmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{NoACLFlags: [4]byte{1, 2, 3, 4}}}}
	// This source property is present but Libc cannot materialize it as acl_t.
	// Ordinary ACL copying must reject it before even capturing the destination.
	for _, stat := range []bool{false, true} {
		backend := &noACLSourceBackend{t: t}
		result, err := hostdata.CopySecurity(source, hostdata.SecurityCopyOptions{ACL: true, Stat: stat}, backend)
		if !errors.Is(err, appledouble.ErrFileSecurity) || result.Completed || result.Writes != 0 || result.Source.Properties.RawSecurity == nil {
			t.Fatal(result, err)
		}
	}
	backend := &noACLSourceBackend{t: t}
	result, err := hostdata.CopySecurity(source, hostdata.SecurityCopyOptions{Stat: true}, backend)
	if err != nil || !result.Completed || result.Writes != 1 || !backend.mode {
		t.Fatal(result, err)
	}
}

type noACLSourceBackend struct {
	t    *testing.T
	mode bool
}

func (b *noACLSourceBackend) CaptureDestinationACL() (*appledouble.ACL, error) {
	b.t.Fatal("unexpected capture")
	return nil, nil
}
func (b *noACLSourceBackend) WriteSecurity(aclmeta.DarwinChmodArguments) error {
	b.t.Fatal("unexpected security write")
	return nil
}
func (b *noACLSourceBackend) Chmod(mode uint16) error {
	if mode != 0644 {
		b.t.Fatal(mode)
	}
	b.mode = true
	return nil
}
func (b *noACLSourceBackend) Chown(uint32, uint32) error { b.t.Fatal("unexpected chown"); return nil }
func (b *noACLSourceBackend) SetACL(*appledouble.ACL) error {
	b.t.Fatal("unexpected ACL write")
	return nil
}
