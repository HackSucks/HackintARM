package acl

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type attributeMetadata struct {
	Security              string
	UID, GID, Mode, Flags uint32
}
type attributeResult struct {
	Code, Errno       int
	After             attributeMetadata
	IdentityUnchanged bool
}
type attributeCorpus struct {
	HelperSHA256, ParentHelperSHA256, SourceSHA256 string
	Conversions                                    []struct {
		Name                     string
		Input, Response, Request []byte
		Expected                 attributeMetadata
	}
	Applications []struct {
		Name, Kind                                               string
		Initial                                                  int
		Mode, Flags                                              uint32
		Text                                                     []byte
		Before                                                   attributeMetadata
		Response, Request, AfterResponse, ReferenceAfterResponse []byte
		Native, Reference                                        attributeResult
	}
}

func readACLAttributesCorpus(t testing.TB) attributeCorpus {
	t.Helper()
	f, e := os.Open("../../../testdata/appledouble/native/acl-attributes.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus attributeCorpus
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if len(corpus.Conversions) != 84 || len(corpus.Applications) != 192 || corpus.SourceSHA256 != "3fcbca58e2d63963115ecd4aa1e27c3d1f7dc21f124897c8bdfdf9916b503c06" {
		t.Fatal("attribute corpus provenance")
	}
	for name, want := range map[string]string{"acl-attributes.c": corpus.HelperSHA256, "filesec.c": corpus.ParentHelperSHA256} {
		b, e := os.ReadFile("../../../testdata/appledouble/native/" + name)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
		if hex.EncodeToString(h[:]) != want {
			t.Fatal("helper provenance", name)
		}
	}
	return corpus
}
func parseACLAttributes(t testing.TB, b []byte) ACLMetadata {
	t.Helper()
	m, e := ParseDarwinACLAttributes(b)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func checkACLAttributesSnapshot(t testing.TB, m ACLMetadata, want attributeMetadata, statView bool) {
	t.Helper()
	b, e := hex.DecodeString(want.Security)
	if e != nil {
		t.Fatal(e)
	}
	s, e := appledouble.ParseDarwinFileSecurity(b)
	if e != nil {
		t.Fatal(e)
	}
	// fstatx_np omits empty ACLs, including no_inherit. Compare that API's
	// narrower view only; the caller separately checks the complete raw frames.
	if statView && s.ACL == nil && s.NoACLFlags == [4]byte{} && m.Security.ACL != nil && len(m.Security.ACL.Entries) == 0 && (m.Security.ACL.Flags == 0 || m.Security.ACL.Flags == 0x20000) {
		clone := *m.Security
		clone.ACL = nil
		m.Security = &clone
	}
	if !sameACLAttributes(m, ACLMetadata{Security: s, UID: want.UID, GID: want.GID, Mode: want.Mode}) {
		t.Fatalf("attribute metadata differs: %#v vs %#v", m, want)
	}
}
func TestNativeACLAttributes(t *testing.T) {
	corpus := readACLAttributesCorpus(t)
	for _, tc := range corpus.Conversions {
		t.Run(tc.Name, func(t *testing.T) {
			m := parseACLAttributes(t, tc.Response)
			checkACLAttributesSnapshot(t, m, tc.Expected, false)
			b, e := m.MarshalDarwinACLAttributes()
			if e != nil || !bytes.Equal(b, tc.Request) {
				t.Fatal("native packing differs", e)
			}
			if len(b) > DarwinACLAttributeBufferSize-4 || DarwinACLCommonAttributes != 0x01c38000 {
				t.Fatal("ABI bounds/mask")
			}
		})
	}
	noops, writes, refusals, differences, flagDifferences := 0, 0, 0, 0, 0
	for _, tc := range corpus.Applications {
		t.Run(tc.Name, func(t *testing.T) {
			before := parseACLAttributes(t, tc.Response)
			checkACLAttributesSnapshot(t, before, tc.Before, true)
			if tc.Before.Mode&07777 != tc.Mode || tc.Before.Flags != tc.Flags {
				t.Fatal("setup mismatch")
			}
			if before.Security.ACL == nil {
				t.Fatal("native getter should retain present ACL")
			}
			count, flags := tc.Initial, uint32(0)
			if count < 0 {
				count = 0
			}
			if tc.Initial == 0 {
				flags = 0x20000
			}
			if len(before.Security.ACL.Entries) != count || before.Security.ACL.Flags != flags {
				t.Fatal("getter lost initial ACL state")
			}
			file := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: tc.Text}}}
			u, e := file.ACLUpdate(nil)
			if e != nil {
				t.Fatal(e)
			}
			m := before
			m.Security, e = u.FileSecurity(before.Security)
			if e != nil {
				t.Fatal(e)
			}
			var request []byte
			if m.Security != nil {
				request, e = m.MarshalDarwinACLAttributes()
				if e != nil {
					t.Fatal(e)
				}
			}
			if !bytes.Equal(request, tc.Request) {
				t.Fatal("native write request differs")
			}
			after := parseACLAttributes(t, tc.AfterResponse)
			checkACLAttributesSnapshot(t, after, tc.Native.After, true)
			reference := parseACLAttributes(t, tc.ReferenceAfterResponse)
			checkACLAttributesSnapshot(t, reference, tc.Reference.After, true)
			for _, r := range []attributeResult{tc.Native, tc.Reference} {
				if !r.IdentityUnchanged || r.After.UID != tc.Before.UID || r.After.GID != tc.Before.GID || r.After.Mode != tc.Before.Mode || r.After.Flags != tc.Before.Flags {
					t.Fatal("write lost identity/metadata")
				}
				if r.Code != 0 && (r.Code != -1 || r.Errno != 1 || r.After != tc.Before) {
					t.Fatal("refusal changed stat metadata")
				}
			}
			if tc.Native.Code != 0 && !bytes.Equal(tc.AfterResponse, tc.Response) {
				t.Fatal("refused attribute write changed ACL flags/entries")
			}
			if tc.Reference.Code != 0 && !bytes.Equal(tc.ReferenceAfterResponse, tc.Response) {
				t.Fatal("refused copyfile write changed ACL flags/entries")
			}
			switch {
			case len(request) == 0:
				noops++
				if tc.Native.Code != 0 || !bytes.Equal(tc.Response, tc.AfterResponse) || !bytes.Equal(tc.Response, tc.ReferenceAfterResponse) {
					t.Fatal("no-op changed attributes")
				}
			case tc.Native.Code == 0:
				writes++
				if !sameACLAttributes(m, after) {
					t.Fatal("accepted write differs from selected metadata")
				}
			default:
				refusals++
			}
			difference := tc.Native != tc.Reference || !bytes.Equal(tc.AfterResponse, tc.ReferenceAfterResponse)
			wantDifference := tc.Initial <= 0 && tc.Flags != 0 && bytes.Equal(tc.Text, []byte("!#acl 1\n"))
			if difference != wantDifference {
				t.Fatal("unexpected attribute/copyfile API difference")
			}
			if difference {
				differences++
				if tc.Native.Errno != 0 || tc.Reference.Errno != 1 {
					t.Fatal("unexpected error difference")
				}
				if !bytes.Equal(tc.AfterResponse, tc.ReferenceAfterResponse) {
					flagDifferences++
					if tc.Initial != 0 || after.Security.ACL.Flags != 0 || reference.Security.ACL.Flags != 0x20000 {
						t.Fatal("unexpected flag difference")
					}
				}
			}
		})
	}
	if noops != 96 || writes != 48 || refusals != 48 || differences != 16 || flagDifferences != 8 {
		t.Fatal("native outcomes changed", noops, writes, refusals, differences, flagDifferences)
	}
}
func TestACLAttributesValidation(t *testing.T) {
	corpus := readACLAttributesCorpus(t)
	var valid []byte
	for _, c := range corpus.Conversions {
		if c.Name == "attributes-pack-1-2-ffffffff" {
			valid = c.Response
		}
	}
	if len(valid) != 148 {
		t.Fatal("missing boundary fixture")
	}
	invalid := func(t *testing.T, b []byte) {
		t.Helper()
		m, e := ParseDarwinACLAttributes(b)
		if !errors.Is(e, ErrDarwinACLAttributes) || !reflect.DeepEqual(m, ACLMetadata{}) {
			t.Fatal("invalid frame accepted", e)
		}
	}
	for i := 0; i < len(valid); i++ {
		t.Run(fmt.Sprintf("truncate-%d", i), func(t *testing.T) { invalid(t, valid[:i]) })
	}
	for _, tc := range []struct {
		name  string
		at    int
		value uint32
	}{
		{"short-frame", 0, 55}, {"oversize-frame", 0, 0xffffffff}, {"negative-reference", 16, 0xffffffff}, {"overlap-reference", 16, 39}, {"far-reference", 16, 0x7fffffff}, {"oversize-reference", 20, 0xffffffff}, {"short-security", 20, 43}, {"security-trailing", 20, 91}, {"bad-magic", 56, 0}, {"too-many-entries", 92, 129},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(valid)
			binary.LittleEndian.PutUint32(b[tc.at:], tc.value)
			invalid(t, b)
		})
	}
	// Independently exercise the allocation ceiling after satisfying frame bounds.
	large := make([]byte, DarwinACLAttributeBufferSize+1)
	copy(large, valid)
	binary.LittleEndian.PutUint32(large, uint32(len(large)))
	binary.LittleEndian.PutUint32(large[20:], 3117)
	invalid(t, large)
	// A valid security record followed by bytes inside the reference is not a
	// kernel-compatible record, even though the lower-level lossless codec accepts it.
	trailing := append(bytes.Clone(valid), 0)
	binary.LittleEndian.PutUint32(trailing, uint32(len(trailing)))
	binary.LittleEndian.PutUint32(trailing[20:], 93)
	invalid(t, trailing)
	want := parseACLAttributes(t, valid)
	if !reflect.DeepEqual(parseACLAttributes(t, append(bytes.Clone(valid), 1, 2, 3)), want) {
		t.Fatal("unused capacity read")
	}
	gap := append(bytes.Clone(valid[:56]), 0, 0, 0, 0)
	gap = append(gap, valid[56:]...)
	binary.LittleEndian.PutUint32(gap, uint32(len(gap)))
	binary.LittleEndian.PutUint32(gap[16:], 44)
	if !reflect.DeepEqual(parseACLAttributes(t, gap), want) {
		t.Fatal("relative reference ignored")
	}
	// Blob ownership is ignored; separate attribute fields are authoritative.
	embedded := bytes.Clone(valid)
	for i := 60; i < 92; i++ {
		embedded[i] = 0x7e
	}
	if !reflect.DeepEqual(parseACLAttributes(t, embedded), want) {
		t.Fatal("ignored ownership slots used")
	}
	for _, s := range []*appledouble.FileSecurity{nil, {Trailing: []byte{1}}, {ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}}, {ACL: &appledouble.ACL{}, NoACLFlags: [4]byte{1}}} {
		if b, e := (ACLMetadata{Security: s}).MarshalDarwinACLAttributes(); b != nil || !errors.Is(e, ErrDarwinACLAttributes) {
			t.Fatal("invalid security encoded", e)
		}
	}
	owned := bytes.Clone(valid)
	m := parseACLAttributes(t, owned)
	clear(owned)
	if !reflect.DeepEqual(m, want) {
		t.Fatal("decoder borrowed input")
	}
	encoded, e := m.MarshalDarwinACLAttributes()
	if e != nil {
		t.Fatal(e)
	}
	clear(encoded)
	if !reflect.DeepEqual(m, want) {
		t.Fatal("encoder mutated/aliased source")
	}
}
func FuzzACLAttributes(f *testing.F) {
	corpus := readACLAttributesCorpus(f)
	for _, c := range corpus.Conversions {
		f.Add(c.Response)
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		original := bytes.Clone(b)
		m, e := ParseDarwinACLAttributes(b)
		if !bytes.Equal(b, original) {
			t.Fatal("input mutation")
		}
		if e != nil {
			if !errors.Is(e, ErrDarwinACLAttributes) {
				t.Fatal("error classification", e)
			}
			return
		}
		request, e := m.MarshalDarwinACLAttributes()
		if e != nil {
			t.Fatal(e)
		}
		if len(request) > DarwinACLAttributeBufferSize-4 {
			t.Fatal("unbounded output")
		}
		response := make([]byte, len(request)+4)
		binary.LittleEndian.PutUint32(response, uint32(len(response)))
		copy(response[4:], request)
		next := parseACLAttributes(t, response)
		if !sameACLAttributes(m, next) {
			t.Fatal("canonical roundtrip lost metadata")
		}
	})
}

// Native binary equality retains nil-vs-empty ACL and every flag/UUID while
// allowing nil-vs-zero-length Go storage for entries/trailing bytes.
func sameACLAttributes(a, b ACLMetadata) bool {
	if a.UID != b.UID || a.GID != b.GID || a.Mode != b.Mode {
		return false
	}
	x, e := a.Security.MarshalDarwinBinary()
	if e != nil {
		return false
	}
	y, e := b.Security.MarshalDarwinBinary()
	return e == nil && bytes.Equal(x, y)
}
