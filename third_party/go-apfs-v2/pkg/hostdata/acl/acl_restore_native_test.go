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

func TestNativeRestoreACL(t *testing.T) {
	f, e := os.Open("../../../testdata/appledouble/native/acl-restore.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	type metadata struct {
		Security              string
		UID, GID, Mode, Flags uint32
	}
	var fixture struct {
		HelperSHA256, ParentHelperSHA256, CopyfileSHA256, XNUSHA256 string
		Cases                                                       []struct {
			Name, Kind, Filesystem string
			Mode, Flags            uint32
			Text                   []byte
			Before                 metadata
			Native                 struct {
				Filesystem                                 string
				Code, Errno                                int
				Applied                                    bool
				After                                      metadata
				IdentityUnchanged, SourceMetadataUnchanged bool
				SourceMask                                 int
				Events                                     []string
				Requests                                   []metadata
			}
			GoResult ACLRestoreResult
		}
	}
	if e = json.NewDecoder(z).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	for name, hash := range map[string]string{"acl-restore.c": fixture.HelperSHA256, "filesec.c": fixture.ParentHelperSHA256} {
		b, e := os.ReadFile("../../../testdata/appledouble/native/" + name)
		if e != nil {
			t.Fatal(e)
		}
		digest := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
		if hex.EncodeToString(digest[:]) != hash {
			t.Fatal("native helper provenance", name)
		}
	}
	if len(fixture.Cases) != 248 || fixture.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || fixture.XNUSHA256 != "6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249" {
		t.Fatal("native corpus/source provenance")
	}
	noops, writes, permission, retries := 0, 0, 0, 0
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var events = []string{}
			attempts := 0
			mask := 7
			decode := func(m metadata) ACLMetadata {
				b, e := hex.DecodeString(m.Security)
				if e != nil {
					t.Fatal(e)
				}
				s, e := appledouble.ParseDarwinFileSecurity(b)
				if e != nil {
					t.Fatal(e)
				}
				return ACLMetadata{Security: s, UID: m.UID, GID: m.GID, Mode: m.Mode}
			}
			destination := decode(tc.Before)
			nativeError := fmt.Errorf("Darwin errno %d", tc.Native.Errno)
			backend := aclRestoreBackend{
				capture: func() (ACLMetadata, error) { events = append(events, "capture"); return destination, nil },
				write: func(m ACLMetadata) error {
					events = append(events, "write")
					if attempts >= len(tc.Native.Requests) {
						t.Fatal("unexpected write")
					}
					want := tc.Native.Requests[attempts]
					attempts++
					b, e := m.Security.MarshalDarwinBinary()
					if e != nil || hex.EncodeToString(b) != want.Security || m.UID != want.UID || m.GID != want.GID || m.Mode != want.Mode {
						t.Fatal("native write request differs", e)
					}
					if tc.Native.Errno == 45 {
						return errors.Join(errors.ErrUnsupported, nativeError)
					}
					if tc.Native.Errno != 0 {
						return nativeError
					}
					return nil
				},
				clear: func() error { events = append(events, "clear-acl", "clear-owner", "clear-group"); mask = 0; return nil },
			}
			file := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: tc.Text}}}
			update, e := file.ACLUpdate(nil)
			if e != nil {
				t.Fatal(e)
			}
			got, e := RestoreACL(update, backend)
			if got != tc.GoResult || got.Applied != tc.Native.Applied || !reflect.DeepEqual(events, tc.Native.Events) || attempts != len(tc.Native.Requests) || mask != tc.Native.SourceMask {
				t.Fatal("native operation sequence differs", got, events, mask)
			}
			if (tc.Native.Errno == 0 && e != nil) || (tc.Native.Errno != 0 && !errors.Is(e, nativeError)) {
				t.Fatal("native error not retained", e)
			}
			if !tc.Native.IdentityUnchanged || !tc.Native.SourceMetadataUnchanged || tc.Native.Filesystem != tc.Filesystem {
				t.Fatal("native identity/source state mismatch")
			}
			after := tc.Native.After
			if after.UID != tc.Before.UID || after.GID != tc.Before.GID || after.Mode != tc.Before.Mode || after.Flags != tc.Before.Flags {
				t.Fatal("native ownership/mode/flags changed")
			}
			if tc.Filesystem == "apfs" && (tc.Before.Mode&07777 != tc.Mode || tc.Before.Flags != tc.Flags) {
				t.Fatal("fixture setup mismatch")
			}
			switch {
			case attempts == 0:
				noops++
				if tc.Native.Code != 0 || after != tc.Before {
					t.Fatal("native no-op changed destination")
				}
			case got.Retried:
				retries++
				if tc.Filesystem != "msdos" || tc.Native.Code != -1 || tc.Native.Errno != 45 || after != tc.Before || tc.Native.Requests[0] != tc.Native.Requests[1] {
					t.Fatal("native retry/refusal mismatch")
				}
			case got.Applied:
				writes++
				if tc.Native.Code != 0 || tc.Native.Errno != 0 {
					t.Fatal("native success mismatch")
				}
			default:
				permission++
				if tc.Native.Code != -1 || tc.Native.Errno != 1 || after != tc.Before {
					t.Fatal("native permission refusal mismatch")
				}
			}
		})
	}
	if noops != 124 || writes != 72 || permission != 48 || retries != 4 {
		t.Fatal("native outcome coverage", noops, writes, permission, retries)
	}
}

func FuzzRestoreACL(f *testing.F) {
	for _, acl := range []*appledouble.ACL{{}, {Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 2}}}} {
		b, _ := acl.MarshalBinary()
		for _, first := range []byte{0, 1, 2} {
			f.Add(b, first, byte(2), false)
			f.Add(b, first, byte(0), true)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte, first, second byte, resetFails bool) {
		if len(b) > 4096 {
			return
		}
		acl, e := appledouble.ParseACLBinary(b)
		if e != nil {
			return
		}
		denied := errors.New("denied")
		classify := func(v byte) error {
			switch v % 3 {
			case 0:
				return nil
			case 1:
				return denied
			default:
				return fmt.Errorf("transport: %w", errors.ErrUnsupported)
			}
		}
		count, resets := 0, 0
		var firstBytes []byte
		backend := aclRestoreBackend{
			capture: func() (ACLMetadata, error) {
				return ACLMetadata{Security: &appledouble.FileSecurity{OwnerUUID: [16]byte{5}, GroupUUID: [16]byte{6}}, UID: 123, GID: 456, Mode: 06755}, nil
			},
			write: func(m ACLMetadata) error {
				count++
				if count > 2 {
					t.Fatal("unbounded retry")
				}
				got, e := m.Security.MarshalBinary()
				if e != nil {
					t.Fatal(e)
				}
				if count == 1 {
					firstBytes = got
				} else if !bytes.Equal(got, firstBytes) {
					t.Fatal("retry mutated")
				}
				if m.UID != 123 || m.GID != 456 || m.Mode != 06755 || m.Security.OwnerUUID[0] != 5 || m.Security.GroupUUID[0] != 6 {
					t.Fatal("metadata lost")
				}
				m.Security.OwnerUUID[0] = 9
				m.Security.ACL.Flags = 9
				if len(m.Security.ACL.Entries) > 0 {
					m.Security.ACL.Entries[0].Rights = 9
				}
				if count == 1 {
					return classify(first)
				}
				return classify(second)
			},
			clear: func() error {
				resets++
				if resetFails {
					return denied
				}
				return nil
			},
		}
		got, e := RestoreACL(appledouble.ACLUpdate{ACL: acl}, backend)
		wantAttempts, wantResets := 1, 0
		cause := classify(first)
		if first%3 == 2 {
			wantResets = 1
			if resetFails {
				cause = denied
			} else {
				wantAttempts = 2
				cause = classify(second)
			}
		}
		if errors.Is(cause, errors.ErrUnsupported) {
			cause = errors.ErrUnsupported
		}
		if got.Attempts != wantAttempts || count != wantAttempts || resets != wantResets || got.Retried != (wantAttempts == 2) || got.Applied != (cause == nil) || !errors.Is(e, cause) {
			t.Fatal("error protocol mismatch", got, e)
		}
	})
}
