package acl

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// Replay native outcomes on every OS. Authorization is measured by the real
// macOS kernel in the capture harness, not implemented by this test backend.
func TestNativeNonOwnerRestoreACL(t *testing.T) {
	f, err := os.Open("../../../testdata/appledouble/native/acl-nonowner.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	type metadata struct {
		Security              string
		UID, GID, Mode, Flags uint32
	}
	type observation struct {
		Metadata                      metadata
		SecurityErrno, AttributeErrno int
		Attributes                    *string
	}
	var corpus struct {
		HelperSHA256, ParentHelperSHA256, CopyfileSHA256 string
		HFSSourceSHA256                                  map[string]string
		Actor                                            struct {
			UID, GID uint32
			Groups   []uint32
		}
		Seeds []struct {
			Name       string
			Text, Disk []byte
		}
		Images []struct{ Filesystem, BeforeSHA256, AfterSHA256 string }
		Cases  []struct {
			Name, Filesystem, Kind, Seed string
			Owner, Group                 bool
			Mode, UID, GID               uint32
			Text, AfterDisk              []byte
			Before                       observation
			Native                       struct {
				Code, Errno, Captures, Writes, Resets int
				Applied, IdentityUnchanged            bool
				After                                 observation
			}
			Request  *DarwinChmodRequest
			GoResult ACLRestoreResult
		}
	}
	if err = json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 1152 || len(corpus.Seeds) != 9 || len(corpus.Images) != 2 || corpus.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		t.Fatal("native corpus provenance")
	}
	wantHFS := map[string]string{"hfs_vnops.c": "a07a8cd9bad0e485a6c7248facac3edcf66736727777715f8cf6a86fb77f3f44", "hfs_xattr.c": "22413ad83654198946ad26797c074fc9c64500a9fe75abbfcff426731ddce117"}
	if !reflect.DeepEqual(corpus.HFSSourceSHA256, wantHFS) {
		t.Fatal("HFS source provenance")
	}
	for path, want := range map[string]string{"acl-nonowner.c": corpus.HelperSHA256, "filesec.c": corpus.ParentHelperSHA256} {
		b, e := os.ReadFile("../../../testdata/appledouble/native/" + path)
		if e != nil {
			t.Fatal(e)
		}
		digest := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
		if hex.EncodeToString(digest[:]) != want {
			t.Fatal("helper provenance", path)
		}
	}
	if corpus.Actor.UID == 0 || corpus.Actor.UID == 60000 || corpus.Actor.GID == 60000 {
		t.Fatal("invalid actor")
	}
	for _, g := range corpus.Actor.Groups {
		if g == 60000 {
			t.Fatal("foreign group belongs to actor")
		}
	}
	seeds := map[string][]byte{}
	for _, s := range corpus.Seeds {
		if _, ok := seeds[s.Name]; ok {
			t.Fatal("duplicate seed")
		}
		seeds[s.Name] = s.Disk
		if s.Name != "none" {
			acl, e := appledouble.ParseACLBinary(s.Disk)
			if e != nil {
				t.Fatal(e)
			}
			b, e := acl.MarshalBinary()
			if e != nil || !bytes.Equal(b, s.Disk) {
				t.Fatal("native seed bytes", e)
			}
		}
	}
	counts := map[string][4]int{}
	for _, im := range corpus.Images {
		if im.Filesystem != "apfs" && im.Filesystem != "hfs" {
			t.Fatal("unknown filesystem")
		}
		if _, ok := counts[im.Filesystem]; ok {
			t.Fatal("duplicate image")
		}
		for _, h := range []string{im.BeforeSHA256, im.AfterSHA256} {
			b, e := hex.DecodeString(h)
			if e != nil || len(b) != 32 {
				t.Fatal("image hash", e)
			}
		}
		if im.BeforeSHA256 == im.AfterSHA256 {
			t.Fatal("image never changed")
		}
		counts[im.Filesystem] = [4]int{}
	}
	names := map[string]bool{}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if names[tc.Name] {
				t.Fatal("duplicate case")
			}
			names[tc.Name] = true
			initial, ok := seeds[tc.Seed]
			if !ok {
				t.Fatal("missing seed")
			}
			uid, gid := uint32(60000), uint32(60000)
			if tc.Owner {
				uid = corpus.Actor.UID
			}
			if tc.Group {
				gid = corpus.Actor.GID
			}
			if tc.UID != uid || tc.GID != gid || tc.Before.Metadata.UID != uid || tc.Before.Metadata.GID != gid || tc.Before.Metadata.Mode&07777 != tc.Mode || tc.Before.Metadata.Flags != 0 {
				t.Fatal("ownership/mode setup")
			}
			kind := uint32(0100000)
			if tc.Kind == "directory" {
				kind = 0040000
			} else if tc.Kind != "file" {
				t.Fatal("unknown kind")
			}
			if tc.Before.Metadata.Mode&0170000 != kind {
				t.Fatal("object kind")
			}
			captures, writes, resets := 0, 0, 0
			nativeError := fmt.Errorf("Darwin errno %d", tc.Native.Errno)
			var request *DarwinChmodRequest
			backend := aclRestoreBackend{
				capture: func() (ACLMetadata, error) {
					captures++
					if tc.Before.SecurityErrno != 0 {
						return ACLMetadata{}, nativeError
					}
					b, e := hex.DecodeString(tc.Before.Metadata.Security)
					if e != nil {
						t.Fatal(e)
					}
					sec, e := appledouble.ParseDarwinFileSecurity(b)
					if e != nil {
						t.Fatal(e)
					}
					return ACLMetadata{Security: sec, UID: uid, GID: gid, Mode: tc.Before.Metadata.Mode}, nil
				},
				write: func(m ACLMetadata) error {
					writes++
					r, e := m.DarwinChmodRequest()
					if e != nil {
						t.Fatal(e)
					}
					request = &r
					if tc.Native.Errno != 0 {
						return nativeError
					}
					return nil
				},
				clear: func() error { resets++; return nil },
			}
			file := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: tc.Text}}}
			update, e := file.ACLUpdate(nil)
			if e != nil {
				t.Fatal(e)
			}
			got, e := RestoreACL(update, backend)
			if got != tc.GoResult || got.Applied != tc.Native.Applied || captures != tc.Native.Captures || writes != tc.Native.Writes || resets != tc.Native.Resets || resets != 0 || got.Retried || !reflect.DeepEqual(request, tc.Request) {
				t.Fatal("native sequence/request differs", got, captures, writes, resets)
			}
			if (tc.Native.Errno == 0 && e != nil) || (tc.Native.Errno != 0 && !errors.Is(e, nativeError)) {
				t.Fatal("native error cause", e)
			}
			after, before := tc.Native.After.Metadata, tc.Before.Metadata
			if !tc.Native.IdentityUnchanged || after.UID != before.UID || after.GID != before.GID || after.Mode != before.Mode || after.Flags != before.Flags {
				t.Fatal("metadata or identity changed")
			}
			if !got.Applied && (!reflect.DeepEqual(tc.Before, tc.Native.After) || !bytes.Equal(tc.AfterDisk, initial)) {
				t.Fatal("failed/no-op restoration changed metadata or offline bytes")
			}
			wantRead := 0
			if tc.Seed == "deny-read" {
				wantRead = 13
			}
			if tc.Before.SecurityErrno != wantRead || tc.Before.AttributeErrno != wantRead || (tc.Before.Attributes == nil) != (wantRead != 0) {
				t.Fatal("security read control")
			}
			// These expectations come from independent native owner/non-owner controls.
			// POSIX mode/group membership alone must not turn into ACL write authority.
			wantErr, wantCaptures, wantWrites, outcome := 0, 0, 0, 0
			if update.ACL != nil {
				wantCaptures = 1
				if wantRead != 0 {
					wantErr = 13
					outcome = 3
				} else {
					wantWrites = 1
					if tc.Owner || tc.Seed == "allow-write" || tc.Seed == "allow-deny" {
						outcome = 1
					} else {
						wantErr = 1
						outcome = 2
					}
				}
			}
			wantCode := 0
			if wantErr != 0 {
				wantCode = -1
			}
			if tc.Native.Errno != wantErr || tc.Native.Code != wantCode || captures != wantCaptures || writes != wantWrites || got.Applied != (outcome == 1) {
				t.Fatal("authorization control", tc.Native.Errno, wantErr)
			}
			if got.Applied {
				sec, e := appledouble.ParseFileSecurity(tc.AfterDisk)
				if e != nil {
					t.Fatal(e)
				}
				gotBytes, marshalErr := sec.ACL.MarshalBinary()
				wantBytes, wantErr := update.ACL.MarshalBinary()
				if marshalErr != nil || wantErr != nil || !bytes.Equal(gotBytes, wantBytes) {
					t.Fatal("offline successful ACL differs")
				}
			}
			c, ok := counts[tc.Filesystem]
			if !ok {
				t.Fatal("unqualified filesystem")
			}
			c[outcome]++
			counts[tc.Filesystem] = c
		})
	}
	for filesystem, c := range counts {
		if c != [4]int{288, 160, 96, 32} {
			t.Fatal("outcome coverage", filesystem, c)
		}
	}
}
