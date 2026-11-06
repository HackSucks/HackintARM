package hostdata

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/pathnative"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

func readMutationFixture(t *testing.T) pathnative.RemovalFixture {
	t.Helper()
	path := os.Getenv("APPLEDOUBLE_MUTATION_FIXTURE")
	retained := path == ""
	if retained {
		path = "../../testdata/appledouble/native/xattr-remove-effects.json.gz"
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var r io.Reader = f
	if retained {
		z, e := gzip.NewReader(f)
		if e != nil {
			t.Fatal(e)
		}
		defer z.Close()
		r = z
	}
	var fixture pathnative.RemovalFixture
	if err := json.NewDecoder(r).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"xattr-remove-effects.c": fixture.HelperSHA256, "xattr-provider-context.h": fixture.ProviderSHA256} {
		b, err := os.ReadFile("../../testdata/appledouble/native/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatal("native mutation observer changed", name)
		}
	}
	if len(fixture.Cases) != 228 {
		t.Fatal("native mutation inventory changed", len(fixture.Cases))
	}
	return fixture
}
func capturedMutation(t *testing.T, operation pathnative.RemovalOperation) CapturedXattrMutation {
	t.Helper()
	effect := CapturedXattrMutation{Name: string(decodeCapturedHex(t, operation.NameHex)), Errno: uint32(operation.Errno)}
	if operation.Code != 0 && operation.Code != -1 || operation.Code == 0 && operation.Errno != 0 || operation.Code == -1 && operation.Errno <= 0 {
		t.Fatal("invalid native operation", operation)
	}
	for i, v := range []pathnative.RemovalValue{operation.Before, operation.After} {
		present := v.SizeErrno == 0
		b := decodeCapturedHex(t, v.Hex)
		if present {
			if v.Size < 0 || v.Read != v.Size || v.Read != len(b) || v.ReadErrno != 0 {
				t.Fatal("incomplete native value", v)
			}
		} else if v.SizeErrno != 93 || v.Size != -1 || v.Read != -1 || v.ReadErrno != 0 || len(b) != 0 {
			t.Fatal("uncaptured native absence", v)
		}
		if i == 0 {
			effect.BeforePresent, effect.Before = present, b
		} else {
			effect.AfterPresent, effect.After = present, b
		}
	}
	return effect
}
func capturedMutationObject(t *testing.T, state pathnative.RemovalContext, attrs []appledouble.StreamAttr, removals []CapturedXattrRemoval, writes []CapturedXattrWrite) *AppleDoubleObject {
	t.Helper()
	uid, gid, mode := state.UID, state.GID, state.Mode
	properties := aclmeta.DarwinChmodProperties{UID: &uid, GID: &gid, Mode: &mode}
	if state.ACLErrno == 0 {
		acl, err := appledouble.ParseACLBinary(decodeCapturedHex(t, state.ACLHex))
		if err != nil {
			t.Fatal(err)
		}
		properties.RawSecurity = &appledouble.FileSecurity{ACL: acl}
	} else if state.ACLErrno != 2 {
		t.Fatal("native ACL unavailable", state.ACLErrno)
	}
	noSetID := state.MountFlags&8 != 0 // Darwin MNT_NOSUID; source, not receiving-host flag.
	object, err := NewCapturedAppleDoubleObject(CapturedAppleDoubleObject{
		State:      MetadataState{Security: SecurityCopySource{UID: uid, GID: gid, Mode: mode, Properties: properties}, Stat: StatCopySource{UID: uid, GID: gid, Mode: mode, Flags: state.Flags}},
		Attributes: attrs, Removals: removals, Writes: writes, NoSetID: &noSetID, Sandboxed: state.Sandboxed,
		Identities: appledouble.ACLIdentitySnapshot{Version: 1}, Process: QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS27, Absent: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return object
}
func TestPathCapturedMutationNativeObservations(t *testing.T) {
	fixture := readMutationFixture(t)
	inventory := map[string]bool{}
	for i, c := range fixture.Cases {
		key := fmt.Sprintf("%s-%o-%t-%d-%d-%t-%t", c.Operation, c.RequestedMode, c.Directory, c.ACLKind, c.RequestedAccess, c.Symlink, c.Dangling)
		if inventory[key] {
			t.Fatal("duplicate native context", key)
		}
		inventory[key] = true
		if !c.CleanupVerified || c.BeforeContext != c.AfterContext {
			t.Fatal("provider identity/context changed", i)
		}
		if c.OpenErrno != 0 {
			if len(c.Operations) != 0 {
				t.Fatal("operations on unopened descriptor", i)
			}
			continue
		}
		t.Run(fmt.Sprintf("%03d-%s", i, key), func(t *testing.T) {
			names, err := parseXattrNames(decodeCapturedHex(t, c.NamesHex))
			if err != nil {
				t.Fatal(err)
			}
			if len(names) != len(c.Operations) || len(names) == 0 {
				t.Fatal("incomplete native operation list")
			}
			var attrs []appledouble.StreamAttr
			var removals []CapturedXattrRemoval
			var writes []CapturedXattrWrite
			expected := map[string]string{}
			for j, op := range c.Operations {
				effect := capturedMutation(t, op)
				if names[j] != effect.Name {
					t.Fatal("native enumeration order lost")
				}
				if effect.BeforePresent {
					attrs = append(attrs, appledouble.StreamAttr{Name: effect.Name, Value: bytes.NewReader(effect.Before)})
					expected[effect.Name] = hex.EncodeToString(effect.Before)
				}
				switch c.Operation {
				case "remove":
					removals = append(removals, effect)
				case "write":
					writes = append(writes, CapturedXattrWrite{Effect: effect, Input: decodeCapturedHex(t, op.InputHex)})
				default:
					t.Fatal("unknown native mutation", c.Operation)
				}
			}
			object := capturedMutationObject(t, c.BeforeContext, attrs, removals, writes)
			for _, op := range c.Operations {
				effect := capturedMutation(t, op)
				var err error
				if c.Operation == "remove" {
					err = object.attrs.remove(effect.Name)
				} else {
					err = object.attrs.write(effect.Name, decodeCapturedHex(t, op.InputHex))
				}
				if effect.Errno == 0 && err != nil || effect.Errno != 0 && !errors.Is(err, CapturedDarwinErrno(effect.Errno)) {
					t.Fatal("captured native result differs", op, err)
				}
				if effect.AfterPresent {
					expected[effect.Name] = hex.EncodeToString(effect.After)
				} else {
					delete(expected, effect.Name)
				}
				_, actual, e := object.LogicalSnapshot()
				if e != nil {
					t.Fatal(e)
				}
				got := map[string]string{}
				for _, a := range actual {
					b, e := io.ReadAll(io.NewSectionReader(a.Value, 0, a.Value.Size()))
					if e != nil {
						t.Fatal(e)
					}
					got[a.Name] = hex.EncodeToString(b)
				}
				if !reflect.DeepEqual(got, expected) {
					t.Fatal("observed native mutation effect differs", got, expected)
				}
			}
		})
	}
	for _, operation := range []string{"remove", "write"} {
		for _, mode := range []int{0400, 0500, 0600, 0700, 0640, 0644, 0755, 0440, 0660} {
			for _, directory := range []bool{false, true} {
				for _, acl := range []int{0, 1, 2} {
					for _, access := range []int{0, 2} {
						key := fmt.Sprintf("%s-%o-%t-%d-%d-false-false", operation, mode, directory, acl, access)
						if !inventory[key] {
							t.Fatal("missing native context", key)
						}
					}
				}
			}
		}
	}
	for _, operation := range []string{"remove", "write"} {
		for _, dangling := range []bool{false, true} {
			for _, acl := range []int{0, 1, 2} {
				key := fmt.Sprintf("%s-%o-false-%d-0-true-%t", operation, 0755, acl, dangling)
				if !inventory[key] {
					t.Fatal("missing held symlink mutation context", key)
				}
			}
		}
	}
}
