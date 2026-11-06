package recompression

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type nativeLookupNode struct {
	UID, GID, Mode, Flags uint32
	SecurityObserved      bool `json:"security_observed"`
	Security              string
}
type nativeLookupCase struct {
	ID, Bytes         string
	CreatedBytes      string `json:"created_bytes"`
	StoredBytes       string `json:"stored_bytes"`
	Existing, Created bool
	Denied            bool `json:"deny_search"`
	Length            int  `json:"native_length"`
	CreateErr         int  `json:"create_errno"`
	OpenErr           int  `json:"open_errno"`
	StatErr           int  `json:"stat_errno"`
	Content           bool `json:"content_matches"`
	Directory, Leaf   *nativeLookupNode
}
type nativeLookupVolume struct {
	Filesystem          string
	UID, GID, Flags     uint32
	Groups              []uint32
	Sensitive           bool `json:"case_sensitive"`
	Capabilities, Valid [4]uint32
	Count               int
	Cleanup             bool `json:"cleanup_complete"`
	Process             int  `json:"long_path_process"`
	ProcessErr          int  `json:"long_path_process_errno"`
	Thread              int  `json:"long_path_thread"`
	ThreadErr           int  `json:"long_path_thread_errno"`
	Cases               []nativeLookupCase
}

func nativeLookupRecipes() map[string][]byte {
	recipes := map[string][]byte{}
	for label, unit := range map[string]string{"ascii": "a", "composed": "é", "decomposed": "e\u0301", "emoji": "😀"} {
		for _, count := range []int{127, 128, 254, 255, 256} {
			recipes[fmt.Sprintf("%s-%d", label, count)] = []byte(strings.Repeat(unit, count))
		}
	}
	for i, raw := range []string{"784179", "78c3a979", "78f09f988079", "78efbfbd79", "78cdb879", "78efb79079", "78f48fbfbf79", "788079", "78c0af79", "78e080af79", "78eda08079", "78f490808079", "78c3", "78007a", "782f79"} {
		b, err := hex.DecodeString(raw)
		if err != nil {
			panic(err)
		}
		recipes[fmt.Sprintf("interface-%d", i)] = b
	}
	for _, n := range []int{254, 255, 256} {
		recipes[fmt.Sprintf("malformed-prefix-%d", n)] = append([]byte{0x80}, bytes.Repeat([]byte{'a'}, n)...)
		recipes[fmt.Sprintf("malformed-suffix-%d", n)] = append(bytes.Repeat([]byte{'a'}, n), 0x80)
	}
	for _, n := range []int{64, 127} {
		recipes[fmt.Sprintf("malformed-emoji-prefix-%d", n)] = append([]byte{0x80}, []byte(strings.Repeat("😀", n))...)
		recipes[fmt.Sprintf("malformed-emoji-suffix-%d", n)] = append([]byte(strings.Repeat("😀", n)), 0x80)
	}
	recipes["invalid-does-not-alias-replacement"] = []byte{'x', 0x80, 'y'}
	for index := 7; index <= 12; index++ {
		recipes[fmt.Sprintf("invalid-percent-alias-%d", index)] = recipes[fmt.Sprintf("interface-%d", index)]
	}
	for _, scalar := range []string{"fffe", "ffff"} {
		raw := "x\ufffe" + "y"
		if scalar == "ffff" {
			raw = "x\uffff" + "y"
		}
		for _, kind := range []string{"direct", "alias"} {
			recipes["noncharacter-"+scalar+"-"+kind] = []byte(raw)
		}
	}
	return recipes
}
func TestNativeNameLookup(t *testing.T) {
	paths := []string{}
	for _, major := range []int{15, 26, 27} {
		paths = append(paths, filepath.Join("..", "..", "testdata", "appledouble", "native", fmt.Sprintf("name-lookup-macos%d.json.gz", major)))
	}
	if fresh := os.Getenv("APFS_NAME_LOOKUP_CAPTURE"); fresh != "" {
		paths = append(paths, fresh)
	}
	for _, name := range paths {
		t.Run(filepath.Base(name), func(t *testing.T) { replayNativeNameLookup(t, name) })
	}
}
func replayNativeNameLookup(t *testing.T, name string) {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(name, ".gz") {
		r, e := gzip.NewReader(bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		raw, e = io.ReadAll(r)
		if e = errors.Join(e, r.Close()); e != nil {
			t.Fatal(e)
		}
	}
	var capture struct {
		Schema          int
		Host            string
		Sources         map[string]string `json:"source_sha256"`
		ExpectedCases   int               `json:"expected_cases"`
		ExpectedVolumes int               `json:"expected_volumes"`
		Detached        bool              `json:"mounts_detached"`
		Volumes         []struct {
			Volume string
			Native nativeLookupVolume
		}
	}
	if err = json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Schema != 1 || capture.ExpectedCases != 1120 || capture.ExpectedVolumes != 5 || len(capture.Volumes) != 5 || !capture.Detached {
		t.Fatal("incomplete native lookup capture")
	}
	version, err := osversion.ParseProductVersion(capture.Host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = osversion.ProfileForMacOS(version); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(filepath.Base(name), "-macos") && !strings.Contains(filepath.Base(name), fmt.Sprintf("-macos%d.", version.Major)) {
		t.Fatal("native lookup target mislabeled")
	}
	verifyNativePathSources(t, name, capture.Sources, "name-lookup.c", "capture-name-lookup.go")
	volumes := map[string]bool{"host": true, "APFS": true, "APFSX": true, "HFS+": true, "HFSX": true}
	for _, volume := range capture.Volumes {
		if !volumes[volume.Volume] {
			t.Fatal("unexpected/duplicate native volume", volume.Volume)
		}
		delete(volumes, volume.Volume)
		n := volume.Native
		if n.UID == 0 || n.Count != 224 || len(n.Cases) != 224 || !n.Cleanup || n.Groups == nil || n.Process != 0 || n.ProcessErr != 0 || n.Thread != 0 || n.ThreadErr != 0 || n.Valid[0]&0x100 == 0 || n.Sensitive != (n.Capabilities[0]&0x100 != 0) {
			t.Fatal("uncaptured native lookup context", volume.Volume)
		}
		if volume.Volume != "host" {
			filesystem := "apfs"
			if strings.HasPrefix(volume.Volume, "HFS") {
				filesystem = "hfs"
			}
			if n.Filesystem != filesystem || n.Sensitive != strings.HasSuffix(volume.Volume, "X") {
				t.Fatal("mounted lookup profile mislabeled", volume.Volume)
			}
		}
		expected := map[string][]byte{}
		for id, recipe := range nativeLookupRecipes() {
			for _, existing := range []bool{false, true} {
				for _, denied := range []bool{false, true} {
					expected[fmt.Sprintf("%s/%t/%t", id, existing, denied)] = recipe
				}
			}
		}
		for _, c := range n.Cases {
			key := fmt.Sprintf("%s/%t/%t", c.ID, c.Existing, c.Denied)
			recipe, ok := expected[key]
			if !ok {
				t.Fatal("duplicate/unexpected native lookup case", key)
			}
			delete(expected, key)
			raw, e := hex.DecodeString(c.Bytes)
			if e != nil || !bytes.Equal(raw, recipe) {
				t.Fatal("native query recipe mismatch", key, e)
			}
			query := string(bytes.SplitN(raw, []byte{0}, 2)[0])
			created := query
			if c.ID == "invalid-does-not-alias-replacement" {
				created = "x\uFFFDy"
			}
			if strings.HasPrefix(c.ID, "invalid-percent-alias-") || strings.HasPrefix(c.ID, "noncharacter-") && strings.HasSuffix(c.ID, "-alias") {
				var spelling strings.Builder
				for _, b := range raw {
					if b < 0x80 {
						spelling.WriteByte(b)
					} else {
						fmt.Fprintf(&spelling, "%%%02X", b)
					}
				}
				created = spelling.String()
			}
			if c.Length != len(query) || c.CreatedBytes != hex.EncodeToString([]byte(created)) {
				t.Fatal("native C-string/create recipe mismatch", key)
			}
			if c.Created != (c.Existing && c.CreateErr == 0) || (!c.Existing && c.CreateErr != 0) || c.Content != (c.OpenErr == 0) || c.OpenErr != c.StatErr || c.Directory == nil || !c.Directory.SecurityObserved || c.Created != (c.Leaf != nil) {
				t.Fatal("incomplete native operation observation", key, c)
			}
			stored, e := hex.DecodeString(c.StoredBytes)
			if e != nil || c.Created != (len(stored) > 0) {
				t.Fatal("uncaptured native directory spelling", key, e)
			}
			t.Run(volume.Volume+"/"+key, func(t *testing.T) { replayNativeNameLookupCase(t, n, c, query, string(stored), version) })
		}
		if len(expected) != 0 {
			t.Fatal("missing native lookup controls")
		}
	}
	if len(volumes) != 0 {
		t.Fatal("missing native lookup volumes")
	}
}
func replayNativeNameLookupCase(t *testing.T, n nativeLookupVolume, c nativeLookupCase, query, created string, version osversion.Version) {
	s, _, m, capture, options := pathFixture(t)
	options.Target = version
	options.Authority.UID = n.UID
	options.Authority.Groups = n.Groups
	records := map[string]metatransport.Record{}
	add := func(name string, record metatransport.Record, observed *nativeLookupNode) {
		if observed == nil || !observed.SecurityObserved {
			t.Fatal("uncaptured native node")
		}
		record.Original = name
		record.Darwin.UID = &observed.UID
		record.Darwin.GID = &observed.GID
		record.Darwin.Mode = &observed.Mode
		record.Darwin.Flags = &observed.Flags
		record.Darwin.Security = nil
		observation := PathObservation{Security: authorization.SecurityAbsent, Mount: authorization.Mount{Identity: "native-volume", Filesystem: n.Filesystem, Flags: n.Flags, CaseSensitive: &n.Sensitive}}
		if observed.Security != "" {
			raw, err := hex.DecodeString(observed.Security)
			if err != nil {
				t.Fatal(err)
			}
			ref := mustBlob(t, s, raw)
			record.Darwin.Security = &ref
			observation.Security = authorization.SecurityPresent
		}
		records[name] = record
		capture.Nodes[name] = observation
	}
	add(".", m.Records[0], c.Directory)
	if c.Created {
		add(created, m.Records[1], c.Leaf)
	}
	evaluator, err := authorization.New(version, options.Authority)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _, actual := resolvePath(t.Context(), s, records, capture, evaluator, query, 1024, osversion.MacOSProfile(version.Major))
	var expected error
	switch c.OpenErr {
	case 0:
	case 2:
		expected = syscall.ENOENT
	case 13:
		expected = syscall.EACCES
	case 63:
		expected = syscall.ENAMETOOLONG
	default:
		t.Fatal("unqualified native O_RDWR error", c.OpenErr)
	}
	if !errors.Is(actual, expected) {
		t.Fatalf("native O_RDWR=%v portable=%v", expected, actual)
	}
	if actual == nil && resolved != created {
		t.Fatal("lookup selected wrong source entry", resolved, created)
	}
}
