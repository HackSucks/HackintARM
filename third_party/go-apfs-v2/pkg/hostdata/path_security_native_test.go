package hostdata

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/pathsecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// This replay does not pretend Go allocations/filesec setters can fail with C
// errno. Every native trace is retained and classified; shared observable policy
// is compared directly, while C-only allocation failures are explicitly scoped.
func TestPathSecurityNativeReplay(t *testing.T) {
	file, err := os.Open("../../testdata/appledouble/native/path-security.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var fixture pathsecurity.Fixture
	if err = json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile("../../testdata/appledouble/native/path-security.c")
	if err != nil {
		t.Fatal(err)
	}
	if fixture.SourceSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || fixture.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(helper)) {
		t.Fatal("native source/observer changed")
	}
	generated := pathsecurity.Cases()
	if len(fixture.Cases) != 579 || len(generated) != len(fixture.Cases) {
		t.Fatal("incomplete native case inventory")
	}
	baselines := map[[5]int]pathsecurity.Observation{}
	for i, c := range fixture.Cases {
		input := c
		input.Native = pathsecurity.Observation{}
		if !reflect.DeepEqual(input, generated[i]) {
			t.Fatal("changed case parameters", i)
		}
		if c.Fault == 0 {
			baselines[[5]int{c.Operation, c.Count, c.First, c.Flags, c.Mode}] = c.Native
		}
	}
	counts := map[string]int{}
	for i, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%03d-op%d-count%d-first%d-flags%d-fault%d", i, c.Operation, c.Count, c.First, c.Flags, c.Fault), func(t *testing.T) {
			if !c.Native.RealEqualsEffectiveUID {
				t.Fatal("fixture identity relation changed; requires separate captured principal mapping")
			}
			base := baselines[[5]int{c.Operation, c.Count, c.First, c.Flags, c.Mode}]
			switch c.Operation {
			case 0:
				native := c.Native
				// These provider failures occur while constructing an unpublished C
				// filesec value. Go uses owned slices and has no corresponding errno API.
				cOnly := native.Code < 0 && native.Errno == 5
				if cOnly {
					counts["C construction fault"]++
					if native.After != nil {
						t.Fatal("failed native preparation published properties")
					}
					native = base
				} else {
					counts["direct preparation"]++
				}
				p := securityReplayProperties(c.Native.Before)
				got, e := PreparePathSecurity(p, [16]byte{9})
				if native.Code < 0 {
					if native.After != nil || c.Count != 128 || !errors.Is(e, appledouble.ErrFileSecurity) {
						t.Fatal("capacity error differs", e, native)
					}
					return
				}
				if e != nil || native.After == nil {
					t.Fatal(e, native)
				}
				if view := securityReplayView(got, false); view != *native.After {
					t.Fatalf("prepared properties differ: got%+v native%+v", view, *native.After)
				}
			case 1:
				// is_uberace constructs a temporary C ACL template. The pure Go policy
				// compares its constants directly and has no fallible template allocation.
				native := c.Native
				templateFault := c.Fault == 9 && slices.Contains(native.Events, "acl-create")
				if templateFault {
					counts["C template fault"]++
					if native.After == nil || native.After.Mode != 0100400 || slices.Contains(native.Events, "acl-delete") {
						t.Fatal("template failure unexpectedly mutated destination")
					}
					native = base
				} else {
					counts["direct reset"]++
				}
				p := securityReplayProperties(c.Native.Before)
				// fchmodx/fstatx omit a zero-entry ACL in native file readback. The
				// in-memory filesec preparation above deliberately retains empty ACLs.
				if p.RawSecurity.ACL != nil && len(p.RawSecurity.ACL.Entries) == 0 {
					p.RawSecurity.ACL = nil
				}
				model := &securityReplayBackend{metadata: aclmeta.ACLMetadata{Mode: 0100400, Security: p.RawSecurity}}
				if !templateFault {
					switch c.Fault {
					case 1:
						model.capture = ErrFilesecAllocation
					case 2:
						model.capture = os.ErrPermission
					case 3:
						model.capture = ErrSecuritySourceNotSupported
					case 4, 5, 6, 7:
						model.write = os.ErrPermission
					case 10:
						model.chmod = os.ErrPermission
					}
				}
				result, e := ResetPathSecurity(model, 0100440, [16]byte{9})
				expectedOps := []string{"capture"}
				if slices.Contains(native.Events, "acl-delete") {
					expectedOps = append(expectedOps, "write")
				}
				if slices.Contains(native.Events, "chmod") {
					expectedOps = append(expectedOps, "chmod")
				}
				if !reflect.DeepEqual(model.operations, expectedOps) {
					t.Fatal("provider order", model.operations, expectedOps, native.Events)
				}
				attemptedFailure := false
				for _, op := range expectedOps {
					var cause error
					switch op {
					case "capture":
						cause = model.capture
					case "write":
						cause = model.write
					case "chmod":
						cause = model.chmod
					}
					if cause != nil {
						attemptedFailure = true
						if !errors.Is(e, cause) {
							t.Fatal("lost ignored native failure", e, cause)
						}
					}
				}
				if !attemptedFailure && e != nil {
					t.Fatal(e)
				}
				if native.After == nil {
					t.Fatal("missing native readback")
				}
				mode := model.metadata.Mode
				got := securityReplayView(aclmeta.DarwinChmodProperties{Mode: &mode, RawSecurity: model.metadata.Security}, true)
				if got != *native.After {
					t.Fatalf("reset state differs: got%+v native%+v result%+v", got, *native.After, result)
				}
				if result.Removed != (slices.Contains(native.Events, "chmodx") && c.Fault != 7 && !templateFault || templateFault && slices.Contains(base.Events, "chmodx")) {
					t.Fatal("ACL publication result", result, native.Events)
				}
			case 2:
				counts["outer absent destination"]++
				if c.Native.Code != 0 || len(c.Native.Events) != 0 || c.Native.After != nil {
					t.Fatal("absent destination reset performs effects")
				}
			default:
				t.Fatal("unknown native operation")
			}
		})
	}
	wantCounts := map[string]int{"C construction fault": 28, "C template fault": 36, "direct preparation": 22, "direct reset": 492, "outer absent destination": 1}
	if !reflect.DeepEqual(counts, wantCounts) {
		t.Fatal("changed native/provider boundary inventory", counts)
	}
	t.Logf("all 579 traces accounted for: %v", counts)
}

func securityReplayProperties(view pathsecurity.Metadata) aclmeta.DarwinChmodProperties {
	p := aclmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{}}
	if view.ModePresent {
		mode := view.Mode
		p.Mode = &mode
	}
	if view.ACLCount >= 0 {
		a := &appledouble.ACL{Entries: make([]appledouble.ACLEntry, view.ACLCount)}
		for i := range a.Entries {
			a.Entries[i] = appledouble.ACLEntry{Principal: [16]byte{1}, Flags: 1 | view.FirstFlags, Rights: 2}
		}
		if len(a.Entries) > 0 {
			a.Entries[0].Flags = uint32(view.FirstTag) | view.FirstFlags
			a.Entries[0].Rights = view.FirstRights
			if view.FirstMatchesRealUID {
				a.Entries[0].Principal = [16]byte{9}
			}
		}
		p.RawSecurity.ACL = a
	}
	return p
}
func securityReplayView(p aclmeta.DarwinChmodProperties, nativeFile bool) pathsecurity.Metadata {
	v := pathsecurity.Metadata{ACLCount: -1}
	if p.Mode != nil {
		v.ModePresent = true
		v.Mode = *p.Mode
		if nativeFile {
			v.Mode |= 0100000
		}
	}
	if p.RawSecurity != nil && p.RawSecurity.ACL != nil {
		a := p.RawSecurity.ACL
		if !nativeFile || len(a.Entries) > 0 {
			v.ACLCount = len(a.Entries)
		}
		if len(a.Entries) > 0 {
			first := a.Entries[0]
			v.FirstRights = first.Rights
			v.FirstTag = int(first.Flags & 0xf)
			v.FirstFlags = first.Flags &^ 0xf
			v.FirstMatchesRealUID = first.Principal == [16]byte{9}
		}
	}
	return v
}

type securityReplayBackend struct {
	metadata              aclmeta.ACLMetadata
	capture, write, chmod error
	operations            []string
}

func (m *securityReplayBackend) CaptureACL() (aclmeta.ACLMetadata, error) {
	m.operations = append(m.operations, "capture")
	return m.metadata, m.capture
}
func (m *securityReplayBackend) WriteACL(value aclmeta.ACLMetadata) error {
	m.operations = append(m.operations, "write")
	if m.write != nil {
		return m.write
	}
	m.metadata = value
	return nil
}
func (m *securityReplayBackend) Chmod(mode uint16) error {
	m.operations = append(m.operations, "chmod")
	if m.chmod != nil {
		return m.chmod
	}
	m.metadata.Mode = uint32(mode)
	return nil
}
