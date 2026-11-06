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

type chmodPropertiesInput struct {
	UID, GID, Mode       *uint32
	OwnerUUID, GroupUUID *[16]byte
	RawSecurity          []byte
	RemoveACL            bool
}

func (p chmodPropertiesInput) properties(t *testing.T) DarwinChmodProperties {
	t.Helper()
	out := DarwinChmodProperties{UID: p.UID, GID: p.GID, Mode: p.Mode, OwnerUUID: p.OwnerUUID, GroupUUID: p.GroupUUID, RemoveACL: p.RemoveACL}
	if p.RawSecurity != nil {
		s, e := appledouble.ParseDarwinFileSecurity(p.RawSecurity)
		if e != nil {
			t.Fatal(e)
		}
		out.RawSecurity = s
	}
	return out
}
func TestNativeChmodProperties(t *testing.T) {
	f, e := os.Open("../../../testdata/appledouble/native/acl-chmod-properties.json.gz")
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
	var corpus struct {
		HelperSHA256, ParentHelperSHA256, LibcSHA256, XNUSHA256, HeaderSHA256 string
		ActorUID, ActorGID                                                    uint32
		Conversions                                                           []struct {
			Name    string
			Input   chmodPropertiesInput
			Request DarwinChmodArguments
		}
		Applications []struct {
			Name, Kind, Profile, SecurityProfile string
			Initial                              int
			Flags                                uint32
			Input                                chmodPropertiesInput
			Before                               metadata
			Response                             []byte
			Request                              DarwinChmodArguments
			Native                               struct {
				Code, Errno                         int
				After                               metadata
				IdentityUnchanged, PayloadUnchanged bool
				Attributes, Filesystem              string
			}
		}
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if len(corpus.Conversions) != 896 || len(corpus.Applications) != 1260 || corpus.LibcSHA256 != "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff" || corpus.XNUSHA256 != "b30d68fb85f34b864b5e71e3127541c2674e0fb52e59d6ee072c8b0ecbb46a4f" || corpus.HeaderSHA256 != "9009cb706a24501dff4f47024c63dc730618249d85dd050f2bf97515a3ca6098" {
		t.Fatal("native corpus provenance")
	}
	for name, want := range map[string]string{"acl-chmod-properties.c": corpus.HelperSHA256, "filesec.c": corpus.ParentHelperSHA256} {
		b, e := os.ReadFile("../../../testdata/appledouble/native/" + name)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
		if hex.EncodeToString(h[:]) != want {
			t.Fatal("helper provenance", name)
		}
	}
	kinds := [3]int{}
	seen := map[string]bool{}
	check := func(name string, input chmodPropertiesInput, want DarwinChmodArguments) {
		t.Helper()
		if seen[name] {
			t.Fatal("duplicate native case")
		}
		seen[name] = true
		p := input.properties(t)
		got, e := p.ChmodArguments()
		if e != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("native arguments differ", name, got, e)
		}
		if input.UID == nil && got.UID != 0xffffff9b || input.GID == nil && got.GID != 0xffffff9b || input.Mode == nil && got.Mode != -1 {
			t.Fatal("omitted numeric properties")
		}
		if input.Mode != nil && got.Mode != int32(uint16(*input.Mode)) {
			t.Fatal("present mode narrowing")
		}
		if got.SecurityArgument == DarwinSecurityRecord {
			sec, e := appledouble.ParseDarwinFileSecurity(got.Security)
			if e != nil {
				t.Fatal(e)
			}
			owner, group := [16]byte{}, [16]byte{}
			if input.OwnerUUID != nil {
				owner = *input.OwnerUUID
			}
			if input.GroupUUID != nil {
				group = *input.GroupUUID
			}
			if sec.OwnerUUID != owner || sec.GroupUUID != group {
				t.Fatal("UUID property precedence")
			}
		} else if got.Security != nil {
			t.Fatal("non-record contains bytes")
		}
		if p.RawSecurity != nil {
			b, e := p.RawSecurity.MarshalDarwinBinary()
			if e != nil || !bytes.Equal(b, input.RawSecurity) {
				t.Fatal("raw input mutated")
			}
		}
	}
	for _, tc := range corpus.Conversions {
		t.Run(tc.Name, func(t *testing.T) {
			check(tc.Name, tc.Input, tc.Request)
			if tc.Request.SecurityArgument > DarwinSecurityRemove {
				t.Fatal("argument kind")
			}
			kinds[tc.Request.SecurityArgument]++
		})
	}
	if kinds != [3]int{32, 832, 32} {
		t.Fatal("security argument controls", kinds)
	}
	successes, refusals, maxRefusals, omittedPreserved, recordClears, removals := 0, 0, 0, 0, 0, 0
	for _, tc := range corpus.Applications {
		t.Run(tc.Name, func(t *testing.T) {
			check(tc.Name, tc.Input, tc.Request)
			n := tc.Native
			if !n.IdentityUnchanged || !n.PayloadUnchanged || n.Filesystem != "apfs" || tc.Before.UID != corpus.ActorUID || tc.Before.GID != corpus.ActorGID || tc.Before.Mode&07777 != 0644 || tc.Before.Flags != tc.Flags {
				t.Fatal("native setup/identity/payload")
			}
			if n.After.UID != tc.Before.UID || n.After.GID != tc.Before.GID || n.After.Flags != tc.Before.Flags {
				t.Fatal("unexpected ownership/flag mutation")
			}
			if n.Code == 0 {
				successes++
				if n.Errno != 0 {
					t.Fatal("native success errno")
				}
				if tc.Input.Mode == nil && n.After.Mode != tc.Before.Mode {
					t.Fatal("omitted mode changed")
				}
				if tc.Input.Mode != nil && n.After.Mode&07777 != *tc.Input.Mode&07777 {
					t.Fatal("explicit mode not applied")
				}
				if tc.Profile == "omitted" && tc.SecurityProfile == "none" {
					omittedPreserved++
					if n.After != tc.Before {
						t.Fatal("null argument changed metadata")
					}
				}
				if tc.Initial == 1 && tc.Flags == 0 && tc.Profile == "omitted" {
					secBytes, e := hex.DecodeString(n.After.Security)
					if e != nil {
						t.Fatal(e)
					}
					sec, e := appledouble.ParseDarwinFileSecurity(secBytes)
					if e != nil {
						t.Fatal(e)
					}
					if tc.SecurityProfile == "noacl" {
						recordClears++
						if sec.ACL != nil {
							t.Fatal("NOACL record effect")
						}
					}
					if tc.SecurityProfile == "remove" {
						removals++
						if sec.ACL != nil {
							t.Fatal("removal effect")
						}
					}
				}
			} else {
				refusals++
				if n.Code != -1 || n.Errno != 1 || n.After != tc.Before {
					t.Fatal("native permission refusal")
				}
				after, e := hex.DecodeString(n.Attributes)
				if e != nil || !bytes.Equal(after, tc.Response) {
					t.Fatal("refused attribute bytes changed")
				}
			}
			if tc.Profile == "explicit-max" {
				maxRefusals++
				if n.Code != -1 || n.Errno != 1 {
					t.Fatal("0xffffffff became omitted UID/GID")
				}
			}
		})
	}
	if successes != 446 || refusals != 814 || maxRefusals != 126 || omittedPreserved != 18 || recordClears != 2 || removals != 2 {
		t.Fatal("native outcome controls", successes, refusals, maxRefusals, omittedPreserved, recordClears, removals)
	}
}

func TestChmodPropertiesValidationAndOwnership(t *testing.T) {
	invalid := []DarwinChmodProperties{{RemoveACL: true, RawSecurity: &appledouble.FileSecurity{}}, {RawSecurity: &appledouble.FileSecurity{Trailing: []byte{1}}}, {RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{}, NoACLFlags: [4]byte{1}}}, {RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}}}}
	for _, p := range invalid {
		got, e := p.ChmodArguments()
		if !errors.Is(e, appledouble.ErrFileSecurity) || !reflect.DeepEqual(got, DarwinChmodArguments{}) {
			t.Fatal("invalid property request", got, e)
		}
	}
	uid, gid, mode := uint32(42), uint32(43), uint32(0xabcd0675)
	owner, group := [16]byte{1}, [16]byte{2}
	sec := &appledouble.FileSecurity{OwnerUUID: [16]byte{9}, GroupUUID: [16]byte{8}, ACL: &appledouble.ACL{Flags: 0x80020000, Entries: []appledouble.ACLEntry{{Flags: 0x80000001, Rights: 0xffffffff}}}}
	p := DarwinChmodProperties{UID: &uid, GID: &gid, Mode: &mode, OwnerUUID: &owner, GroupUUID: &group, RawSecurity: sec}
	before, e := sec.MarshalDarwinBinary()
	if e != nil {
		t.Fatal(e)
	}
	first, e := p.ChmodArguments()
	if e != nil {
		t.Fatal(e)
	}
	second, e := p.ChmodArguments()
	if e != nil || !reflect.DeepEqual(first, second) {
		t.Fatal(e)
	}
	first.Security[4] = 99
	if second.Security[4] != 1 || owner[0] != 1 || sec.OwnerUUID[0] != 9 {
		t.Fatal("output aliases input/another output")
	}
	uid, gid, mode = 99, 99, 99
	owner[0], group[0] = 99, 99
	sec.ACL.Entries[0].Rights = 0
	if second.UID != 42 || second.GID != 43 || second.Mode != 0x0675 || second.Security[4] != 1 || second.Security[20] != 2 {
		t.Fatal("input aliases output")
	}
	// Only the deliberate test mutation may have changed the raw input.
	sec.ACL.Entries[0].Rights = 0xffffffff
	after, e := sec.MarshalDarwinBinary()
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("raw property mutated")
	}
}

func FuzzDarwinChmodProperties(f *testing.F) {
	for _, sec := range []*appledouble.FileSecurity{{}, {NoACLFlags: [4]byte{1, 2, 3, 4}}, {ACL: &appledouble.ACL{}}, {ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 0xffffffff, Rights: 0xffffffff}}}}} {
		b, _ := sec.MarshalDarwinBinary()
		f.Add(b, byte(63), uint32(0xffffffff))
		f.Add(b, byte(0), uint32(0))
	}
	f.Fuzz(func(t *testing.T, b []byte, mask byte, n uint32) {
		if len(b) > 4096 {
			return
		}
		sec, e := appledouble.ParseDarwinFileSecurity(b)
		if e != nil {
			return
		}
		owner, group := [16]byte{1}, [16]byte{2}
		p := DarwinChmodProperties{RemoveACL: mask&64 != 0}
		if mask&1 != 0 {
			p.UID = &n
		}
		if mask&2 != 0 {
			p.GID = &n
		}
		if mask&4 != 0 {
			p.Mode = &n
		}
		if mask&8 != 0 {
			p.OwnerUUID = &owner
		}
		if mask&16 != 0 {
			p.GroupUUID = &group
		}
		if mask&32 != 0 {
			p.RawSecurity = sec
		}
		before, _ := sec.MarshalDarwinBinary()
		got, e := p.ChmodArguments()
		after, _ := sec.MarshalDarwinBinary()
		if !bytes.Equal(before, after) {
			t.Fatal("input mutated")
		}
		invalid := p.RawSecurity != nil && (p.RemoveACL || len(sec.Trailing) != 0)
		if e != nil {
			if !invalid || !errors.Is(e, appledouble.ErrFileSecurity) || !reflect.DeepEqual(got, DarwinChmodArguments{}) {
				t.Fatal("error contract", e)
			}
			return
		}
		if invalid {
			t.Fatal("invalid request accepted")
		}
		if got.Mode < -1 || got.Mode > 65535 || len(got.Security) > 3116 {
			t.Fatal("argument bounds")
		}
		if p.UID == nil && got.UID != 0xffffff9b || p.GID == nil && got.GID != 0xffffff9b || p.Mode == nil && got.Mode != -1 {
			t.Fatal("omitted values")
		}
		other, e := p.ChmodArguments()
		if e != nil || !reflect.DeepEqual(got, other) {
			t.Fatal("unstable request")
		}
		if got.SecurityArgument == DarwinSecurityRecord {
			parsed, e := appledouble.ParseDarwinFileSecurity(got.Security)
			if e != nil {
				t.Fatal(e)
			}
			round, e := parsed.MarshalDarwinBinary()
			if e != nil || !bytes.Equal(round, got.Security) {
				t.Fatal("record roundtrip")
			}
			got.Security[0] ^= 1
			if bytes.Equal(got.Security, other.Security) {
				t.Fatal("request storage shared")
			}
		} else if got.Security != nil {
			t.Fatal("non-record storage")
		}
	})
}
