package hostdata

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/pathnative"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	xattrintent "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/xattrintent"
)

// The retained file is a host-context observation, not a universal ambient-host
// golden. Replay its complete captured byte inputs directly on every OS. Native
// path acquisition/authorization is independently compared on the live host.
func TestPathCapturedNativePack(t *testing.T) {
	fixture := readCapturedPathFixture(t)
	counts := map[string]int{}
	for index, c := range fixture.Cases {
		if c.Route != 0 {
			counts["unpack"]++
			continue
		}
		canceled := c.Quit != 0 && len(c.Native.Notices) > 0
		if !(c.Native.Code == 0 && c.Native.DestinationSHA256 != "") && !canceled {
			counts["outer acquisition or destination IO"]++
			continue
		}
		counts["packing"]++
		t.Run(fmt.Sprintf("%03d", index), func(t *testing.T) {
			attributes, security := c.Native.Input.SourceFollow, c.Native.Input.SourceSecurityFollow
			if c.Selected&4 != 0 {
				attributes, security = c.Native.Input.SourceNoFollow, c.Native.Input.SourceSecurityNoFollow
			}
			backend := &capturedPathPack{attributes: attributes, security: security, sandboxed: c.Native.Input.Sandboxed, profile: capturedPathProfile(t, fixture.Host)}
			opts := DefaultObjectPackOptions().PackOptions
			opts.CopyACL = c.Selected&32 != 0
			for _, value := range attributes.Values {
				if string(decodeCapturedHex(t, value.NameHex)) == appledouble.QuarantineName {
					opts.HasQuarantine = true
				}
			}
			var notices []pathnative.Notice
			if c.Selected&64 != 0 || c.Quit != 0 {
				opts.Callback = func(n PackNotice) CopyPipelineAction {
					stage := map[PackEvent]int{PackStart: 1, PackFinish: 2, PackError: 3, PackProgress: 4}[n.Event]
					notices = append(notices, pathnative.Notice{What: 5, Stage: stage, Copied: int64(n.Copied)})
					if canceled {
						return CopyPipelineQuit
					}
					return CopyPipelineContinue
				}
			}
			result, err := PackAppleDouble(context.Background(), opts, backend)
			if result.Code != c.Native.Code || (result.Code < 0) != (err != nil) {
				t.Fatal("captured native return differs", result, err, c.Native.Code)
			}
			if len(notices) != len(c.Native.Notices) || (len(notices) > 0 && !reflect.DeepEqual(notices, c.Native.Notices)) {
				t.Fatal("native callbacks differ", notices, c.Native.Notices)
			}
			if canceled {
				if !errors.Is(err, ErrPackCanceled) {
					t.Fatal("native callback cancellation lost", err)
				}
				return
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(backend.output)); got != c.Native.DestinationSHA256 {
				t.Fatalf("captured C output differs: got%s want%s; all %d raw source attributes retained", got, c.Native.DestinationSHA256, len(attributes.Values))
			}
			if int64(len(backend.output)) != c.Native.After.Size {
				t.Fatal("captured C output length differs", len(backend.output), c.Native.After.Size)
			}
		})
	}
	// This inventory is updated only alongside a reviewed expanded C capture.
	if !reflect.DeepEqual(counts, map[string]int{"packing": 112, "unpack": 307, "outer acquisition or destination IO": 133}) {
		t.Fatal("unaccounted capture cases", counts)
	}
	t.Logf("retained context-bound native wire replay: %v", counts)
}
func readCapturedPathFixture(t *testing.T) pathnative.Fixture {
	t.Helper()
	f, e := os.Open("../../testdata/appledouble/native/path-copyfile.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var fixture pathnative.Fixture
	if e = json.NewDecoder(z).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	source, e := os.ReadFile("../../testdata/appledouble/native/path-copyfile.c")
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprintf("%x", sha256.Sum256(source)) != fixture.HelperSHA256 {
		t.Fatal("native observer provenance differs")
	}
	provider, e := os.ReadFile("../../testdata/appledouble/native/xattr-provider-context.h")
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprintf("%x", sha256.Sum256(provider)) != fixture.ProviderSHA256 {
		t.Fatal("native provider observer changed")
	}
	cases := pathnative.Cases()
	if len(cases) != 552 || len(fixture.Cases) != len(cases) {
		t.Fatal("native inventory changed", len(fixture.Cases))
	}
	for i, c := range fixture.Cases {
		spec := c
		spec.Native = pathnative.Observation{}
		if !reflect.DeepEqual(spec, cases[i]) {
			t.Fatal("native case input changed", i)
		}
		for _, input := range []pathnative.AttributeContext{c.Native.Input.SourceFollow, c.Native.Input.SourceNoFollow, c.Native.Input.DestinationFollow, c.Native.Input.DestinationNoFollow, c.Native.Input.Target, c.Native.Output.SourceFollow, c.Native.Output.SourceNoFollow, c.Native.Output.DestinationFollow, c.Native.Output.DestinationNoFollow, c.Native.Output.Target} {
			validateCapturedAttributes(t, input)
		}
	}
	return fixture
}
func validateCapturedAttributes(t *testing.T, input pathnative.AttributeContext) {
	t.Helper()
	names := decodeCapturedHex(t, input.NamesHex)
	if input.SizeErrno != 0 {
		if input.Size >= 0 || input.Read != -1 || len(names) != 0 || len(input.Values) != 0 {
			t.Fatal("malformed failed enumeration capture", input)
		}
		return
	}
	if input.ReadErrno != 0 {
		if input.Read >= 0 || len(names) != 0 || len(input.Values) != 0 {
			t.Fatal("malformed failed names capture", input)
		}
		return
	}
	if input.Size < 0 || input.Read != len(names) || input.Read > input.Size {
		t.Fatal("incomplete names capture", input)
	}
	parsed, e := parseXattrNames(names)
	if e != nil {
		t.Fatal(e)
	}
	if len(parsed) != len(input.Values) {
		t.Fatal("attribute record omitted", parsed, input.Values)
	}
	for i, v := range input.Values {
		if parsed[i] != string(decodeCapturedHex(t, v.NameHex)) {
			t.Fatal("native attribute order changed")
		}
		value := decodeCapturedHex(t, v.Hex)
		if v.SizeErrno != 0 {
			if v.Size >= 0 || v.Read != -1 || len(value) != 0 {
				t.Fatal("malformed failed size capture", v)
			}
		} else if v.ReadErrno != 0 {
			if v.Read >= 0 || len(value) != 0 {
				t.Fatal("malformed failed value capture", v)
			}
		} else if v.Size < 0 || v.Read != len(value) || v.Read > v.Size {
			t.Fatal("incomplete native value capture", v)
		}
	}
}
func decodeCapturedHex(t *testing.T, text string) []byte {
	t.Helper()
	b, e := hex.DecodeString(text)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func capturedPathProfile(t *testing.T, host string) appledouble.QuarantineProfile {
	t.Helper()
	for _, p := range []struct {
		version string
		profile appledouble.QuarantineProfile
	}{{"26.", appledouble.QuarantineMacOS26}, {"27.", appledouble.QuarantineMacOS27}} {
		if strings.Contains(host, "\t"+p.version) {
			return p.profile
		}
	}
	t.Fatal("uncaptured quarantine OS profile")
	return 0
}

type capturedPathPack struct {
	attributes pathnative.AttributeContext
	security   pathnative.SourceSecurity
	sandboxed  bool
	profile    appledouble.QuarantineProfile
	output     objectOutput
}

func (b *capturedPathPack) Names(capacity int) ([]string, error) {
	if b.attributes.SizeErrno != 0 {
		return nil, syscall.Errno(b.attributes.SizeErrno)
	}
	if b.attributes.ReadErrno != 0 {
		return nil, syscall.Errno(b.attributes.ReadErrno)
	}
	data, e := hex.DecodeString(b.attributes.NamesHex)
	if e != nil {
		return nil, e
	}
	if len(data) > capacity {
		return nil, syscall.Errno(34)
	}
	return parseXattrNames(data)
}
func (b *capturedPathPack) find(name string) (pathnative.AttributeValue, error) {
	for _, v := range b.attributes.Values {
		n, e := hex.DecodeString(v.NameHex)
		if e != nil {
			return v, e
		}
		if string(n) == name {
			return v, nil
		}
	}
	return pathnative.AttributeValue{}, syscall.Errno(93)
}
func (b *capturedPathPack) XattrSize(name string) (int64, error) {
	v, e := b.find(name)
	if e != nil {
		return 0, e
	}
	if v.SizeErrno != 0 {
		return int64(v.Size), syscall.Errno(v.SizeErrno)
	}
	return int64(v.Size), nil
}
func (b *capturedPathPack) ReadXattr(name string, dst []byte) (int, error) {
	v, e := b.find(name)
	if e != nil {
		return -1, e
	}
	if v.ReadErrno != 0 {
		return v.Read, syscall.Errno(v.ReadErrno)
	}
	data, e := hex.DecodeString(v.Hex)
	if e != nil {
		return -1, e
	}
	if len(data) > len(dst) {
		return -1, syscall.Errno(34)
	}
	return copy(dst, data), nil
}
func (b *capturedPathPack) ACLPresent() (bool, error) {
	if b.security.StatErrno != 0 {
		return false, syscall.Errno(b.security.StatErrno)
	}
	if b.security.ACLErrno == 2 {
		return false, nil
	}
	if b.security.ACLErrno != 0 {
		return false, syscall.Errno(b.security.ACLErrno)
	}
	if b.security.ACLHex == "" {
		return false, errors.New("ACL presence not captured")
	}
	return true, nil
}
func (b *capturedPathPack) ACL() ([]byte, error) {
	data, e := hex.DecodeString(b.security.ACLHex)
	if e != nil {
		return nil, e
	}
	acl, e := appledouble.ParseACLBinary(data)
	if e != nil {
		return nil, e
	}
	text, e := acl.MarshalText()
	return append(text, 0), e
}
func (b *capturedPathPack) Quarantine() ([]byte, error) {
	v, e := b.find(appledouble.QuarantineName)
	if e != nil {
		return nil, e
	}
	data, e := hex.DecodeString(v.Hex)
	if e != nil {
		return nil, e
	}
	q, e := appledouble.ParseQuarantineXattrWithProfile(data, b.profile)
	if e != nil {
		return nil, e
	}
	return q.MarshalBinaryWithProfile(b.profile)
}
func (b *capturedPathPack) PreserveForIntent(name string, intent uint32) bool {
	return xattrintent.PreserveXattrForIntent(name, intent, b.sandboxed)
}
func (b *capturedPathPack) WriteAt(data []byte, offset int64) (int, error) {
	return b.output.WriteAt(data, offset)
}

// Stat effects are outside this byte/callback replay and have independent path,
// native object and ordered-stat corpora. No native authorization is invented.
func (*capturedPathPack) Stat() CopyStageResult { return CopyStageResult{} }

// This replay uses the captured wire and an existing captured destination. Path
// creation, source-link acquisition and replacement are covered by their own
// path corpus; they cannot be inferred from a before/after xattr observation.
func TestPathCapturedNativeUnpack(t *testing.T) {
	fixture := readCapturedPathFixture(t)
	mutations := readMutationFixture(t)
	counts := map[string]int{}
	for index, c := range fixture.Cases {
		if c.Route != 1 {
			counts["pack"]++
			continue
		}
		input := c.Native.Input
		if c.Native.Code != 0 || input.SourceData.NotRegular || input.SourceData.Errno != 0 || (c.SourceKind == 3 && c.Selected&4 != 0) || c.Selected&8 != 0 || c.NullSource {
			counts["outer acquisition, replacement or native failure"]++
			continue
		}
		before, after := input.DestinationFollow, c.Native.Output.DestinationFollow
		if c.Selected&4 != 0 {
			before, after = input.DestinationNoFollow, c.Native.Output.DestinationNoFollow
		}
		if before.SizeErrno != 0 || before.ReadErrno != 0 {
			counts["destination creation"]++
			continue
		}
		counts["unpacking"]++
		t.Run(fmt.Sprintf("%03d", index), func(t *testing.T) {
			var attrs []appledouble.StreamAttr
			for _, a := range before.Values {
				attrs = append(attrs, appledouble.StreamAttr{Name: string(decodeCapturedHex(t, a.NameHex)), Value: bytes.NewReader(decodeCapturedHex(t, a.Hex))})
			}
			provider := input.DestinationProviderFollow
			if c.Selected&4 != 0 {
				provider = input.DestinationProviderNoFollow
			}
			if provider.OpenErrno != 0 {
				t.Fatal("missing native destination provider", provider.OpenErrno)
			}
			state, removals := matchedPathRemovalContext(t, provider.State, before, mutations)
			source, destination := objectFixture(t), capturedMutationObject(t, state, attrs, removals, nil)
			options := DefaultObjectUnpackOptions()
			options.Stat, options.Sandboxed = c.Selected&1 != 0, input.Sandboxed
			var notices []pathnative.Notice
			if c.Selected&64 != 0 || c.Quit != 0 {
				options.Callback = func(n UnpackNotice) CopyPipelineAction {
					stage := map[XattrRestoreEvent]int{XattrRestoreStart: 1, XattrRestoreFinish: 2, XattrRestoreError: 3}[n.Event]
					notices = append(notices, pathnative.Notice{What: 5, Stage: stage, Copied: int64(n.Copied)})
					if c.Quit != 0 {
						return CopyPipelineQuit
					}
					return CopyPipelineContinue
				}
			}
			result := ObjectUnpackResult{}
			backend := &objectUnpackBackend{ctx: context.Background(), source: source, destination: destination, options: options, result: &result}
			got, err := RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(decodeCapturedHex(t, input.SourceData.Hex)), options.UnpackSequentialOptions, backend)
			if got.Code != c.Native.Code || err != nil {
				t.Fatal("native unpack return differs", got, err)
			}
			if len(notices) != len(c.Native.Notices) || (len(notices) > 0 && !reflect.DeepEqual(notices, c.Native.Notices)) {
				t.Fatal("native callbacks differ", notices, c.Native.Notices)
			}
			_, actual, err := destination.LogicalSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			actualMap := map[string]string{}
			for _, a := range actual {
				b := make([]byte, a.Value.Size())
				if _, err := a.Value.ReadAt(b, 0); err != nil {
					t.Fatal(err)
				}
				actualMap[hex.EncodeToString([]byte(a.Name))] = hex.EncodeToString(b)
			}
			expected := map[string]string{}
			for _, a := range after.Values {
				if a.SizeErrno != 0 || a.ReadErrno != 0 {
					t.Fatal("incomplete final attribute", a)
				}
				expected[a.NameHex] = a.Hex
			}
			if !reflect.DeepEqual(actualMap, expected) {
				t.Fatal("complete captured destination namespace differs", actualMap, expected)
			}
		})
	}
	if !reflect.DeepEqual(counts, map[string]int{"pack": 245, "unpacking": 40, "destination creation": 13, "outer acquisition, replacement or native failure": 254}) {
		t.Fatal("native unpack replay inventory changed", counts)
	}
	t.Logf("retained context-bound unpack replay: %v", counts)
}

// Match actual provider contexts after the independently qualified temporary
// permission stage. Only inode identity differs between separately owned files;
// owner, volume/device, mode, ACL, process, sandbox and access must all agree.
func matchedPathRemovalContext(t *testing.T, initial pathnative.RemovalContext, attributes pathnative.AttributeContext, fixture pathnative.RemovalFixture) (pathnative.RemovalContext, []CapturedXattrRemoval) {
	t.Helper()
	for _, c := range fixture.Cases {
		if c.Operation != "remove" || c.OpenErrno != 0 {
			continue
		}
		uid, gid, mode := initial.UID, initial.GID, initial.Mode
		properties := aclmeta.DarwinChmodProperties{UID: &uid, GID: &gid, Mode: &mode}
		var realUser [16]byte
		if initial.ACLErrno == 0 {
			acl, err := appledouble.ParseACLBinary(decodeCapturedHex(t, initial.ACLHex))
			if err != nil {
				t.Fatal(err)
			}
			properties.RawSecurity = &appledouble.FileSecurity{ACL: acl}
			if c.ACLKind != 2 || c.BeforeContext.ACLErrno != 0 {
				continue
			}
			observed, err := appledouble.ParseACLBinary(decodeCapturedHex(t, c.BeforeContext.ACLHex))
			if err != nil {
				t.Fatal(err)
			}
			if len(observed.Entries) == 0 || observed.Entries[0].Flags != 1 || observed.Entries[0].Rights != TemporaryWriteRights {
				t.Fatal("independent temporary owner ACE not captured")
			}
			// The C probe obtains this principal independently from mbr_uid_to_uuid
			// for the captured real UID; no account lookup occurs on the replay host.
			realUser = observed.Entries[0].Principal
		} else if initial.ACLErrno != 2 {
			t.Fatal("uncaptured destination ACL", initial.ACLErrno)
		}
		prepared, err := PreparePathSecurity(properties, realUser)
		if err != nil {
			t.Fatal(err)
		}
		expected := initial
		expected.Mode = *prepared.Mode
		if prepared.RawSecurity != nil {
			b, err := prepared.RawSecurity.ACL.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			expected.ACLHex = hex.EncodeToString(b)
		}
		observed := c.BeforeContext
		expected.Inode, observed.Inode = 0, 0
		if expected != observed {
			continue
		}
		var effects []CapturedXattrRemoval
		for _, a := range attributes.Values {
			for _, op := range c.Operations {
				if op.NameHex != a.NameHex {
					continue
				}
				effect := capturedMutation(t, op)
				if !effect.BeforePresent || hex.EncodeToString(effect.Before) != a.Hex {
					t.Fatal("native provider observation has different pre-state", a.NameHex)
				}
				effects = append(effects, effect)
			}
		}
		if len(effects) == 0 {
			t.Fatal("matched native context has no overlapping mutation observations")
		}
		return c.BeforeContext, effects
	}
	t.Fatalf("native mutation-time provider context not qualified: %+v", initial)
	return pathnative.RemovalContext{}, nil
}
