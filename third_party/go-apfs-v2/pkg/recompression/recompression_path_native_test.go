package recompression

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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type nativePathLimitCase struct {
	ID, Created, Queried, Target string
	Mode                         uint32 `json:"directory_mode"`
	CreateErr                    int    `json:"create_errno"`
	LookupErr                    int    `json:"lookup_errno"`
}
type nativePathLimits struct {
	Capabilities  [4]uint32
	Valid         [4]uint32
	CapabilityErr int `json:"capability_errno"`
	Groups        []uint32
	UID           uint32 `json:"actor_uid"`
	GID           uint32 `json:"actor_gid"`
	Filesystem    string
	Flags         uint32 `json:"mount_flags"`
	Cases         []nativePathLimitCase
	RootSecurity  string `json:"root_security"`
	LeafSecurity  string `json:"leaf_security"`
	ACLEmpty      bool   `json:"fixture_acl_observed_empty"`
	Cleanup       bool   `json:"cleanup_complete"`
	Process       int    `json:"long_path_process"`
	ProcessErr    int    `json:"long_path_process_errno"`
	Thread        int    `json:"long_path_thread"`
	ThreadErr     int    `json:"long_path_thread_errno"`
	SetProcessErr int    `json:"set_long_path_process_errno"`
	SetThreadErr  int    `json:"set_long_path_thread_errno"`
}

func pathLimitIDs() map[string]bool {
	ids := map[string]bool{"empty-input": true, "embedded-nul-c-string": true, "no-search-empty": true, "no-search-short": true, "no-search-component-256": true, "no-search-path-1023": true, "no-search-path-1024": true}
	for n := 1022; n <= 1025; n++ {
		ids[fmt.Sprintf("relative-components-%d", n)] = true
	}
	for n := 31; n <= 33; n++ {
		ids[fmt.Sprintf("symlinks-%d", n)] = true
	}
	for n := 1022; n <= 1024; n++ {
		for _, suffix := range []string{"plain-700", "slash-700", "child-700", "slash-600"} {
			ids[fmt.Sprintf("expansion-%d-%s", n, suffix)] = true
		}
	}
	return ids
}
func TestNativePathLimits(t *testing.T) {
	paths := []string{}
	for _, major := range []int{15, 26, 27} {
		paths = append(paths, filepath.Join("..", "..", "testdata", "appledouble", "native", fmt.Sprintf("pathname-limits-macos%d.json.gz", major)))
	}
	if fresh := os.Getenv("APFS_PATHNAME_LIMITS_CAPTURE"); fresh != "" {
		paths = append(paths, fresh)
	}
	for _, name := range paths {
		t.Run(filepath.Base(name), func(t *testing.T) { replayNativePathLimits(t, name) })
	}
}
func replayNativePathLimits(t *testing.T, name string) {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(name, ".gz") {
		reader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		raw, err = io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if err = reader.Close(); err != nil {
			t.Fatal(err)
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
			Native nativePathLimits
		}
	}
	if err = json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Schema != 1 || capture.ExpectedCases != 130 || capture.ExpectedVolumes != 5 || len(capture.Volumes) != 5 || !capture.Detached {
		t.Fatal("incomplete native path-limit capture")
	}
	version, err := osversion.ParseProductVersion(capture.Host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = osversion.ProfileForMacOS(version); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(filepath.Base(name), "-macos") && !strings.Contains(filepath.Base(name), fmt.Sprintf("-macos%d.", version.Major)) {
		t.Fatal("native fixture target mislabeled")
	}
	verifyNativePathSources(t, name, capture.Sources, "pathname-limits.c", "capture-pathname-limits.go")
	volumes := map[string]bool{"host": true, "APFS": true, "APFSX": true, "HFS+": true, "HFSX": true}
	for _, volume := range capture.Volumes {
		if !volumes[volume.Volume] {
			t.Fatal("duplicate/unexpected volume", volume.Volume)
		}
		delete(volumes, volume.Volume)
		n := volume.Native
		if n.CapabilityErr != 0 || n.Valid[0]&0x100 == 0 {
			t.Fatal("uncaptured native case-comparison policy")
		}
		if len(n.Cases) != 26 || !n.Cleanup || n.Groups == nil || !n.ACLEmpty || n.ProcessErr != 0 || n.ThreadErr != 0 || n.Process != 0 || n.Thread != 0 {
			t.Fatal("uncaptured ordinary native path context", volume.Volume)
		}
		// Failed private-policy enable attempts are retained as failed setup. They
		// are never treated as a successful native long-path qualification.
		if n.SetProcessErr != 1 || n.SetThreadErr != 1 {
			t.Fatal("native long-path enable outcome needs qualification", n.SetProcessErr, n.SetThreadErr)
		}
		if volume.Volume != "host" {
			filesystem := "apfs"
			if strings.HasPrefix(volume.Volume, "HFS") {
				filesystem = "hfs"
			}
			if n.Filesystem != filesystem || (n.Capabilities[0]&0x100 != 0) != strings.HasSuffix(volume.Volume, "X") {
				t.Fatal("mounted path profile mislabeled", volume.Volume)
			}
		}
		ids := pathLimitIDs()
		for _, c := range n.Cases {
			if !ids[c.ID] {
				t.Fatal("duplicate/unexpected native limit case", c.ID)
			}
			delete(ids, c.ID)
			t.Run(volume.Volume+"/"+c.ID, func(t *testing.T) { replayNativePathLimitCase(t, n, c, version) })
		}
		if len(ids) != 0 {
			t.Fatal("missing native path-limit cases")
		}
	}
	if len(volumes) != 0 {
		t.Fatal("missing native volumes")
	}
}
func replayNativePathLimitCase(t *testing.T, n nativePathLimits, c nativePathLimitCase, version osversion.Version) {
	// This is lookup-only replay. The substrate's payload/timestamps are not part
	// of the observed operation; source ownership, mode, ACL and namespace are.
	s, _, m, capture, options := pathFixture(t)
	options.Target = version
	options.Authority.UID = n.UID
	options.Authority.Groups = n.Groups
	root, file := m.Records[0], m.Records[1]
	root.Darwin.UID = &n.UID
	root.Darwin.GID = &n.GID
	file.Darwin.UID = &n.UID
	file.Darwin.GID = &n.GID
	mode := c.Mode
	if mode == 0 {
		mode = 0700
	}
	mode |= 0040000
	root.Darwin.Mode = &mode
	leafMode := uint32(0100600)
	file.Darwin.Mode = &leafMode
	for _, entry := range []struct {
		name     string
		record   *metatransport.Record
		security string
	}{{".", &root, n.RootSecurity}, {"file", &file, n.LeafSecurity}} {
		observation := capture.Nodes[entry.name]
		observation.Mount.Filesystem = n.Filesystem
		observation.Mount.Flags = n.Flags
		caseSensitive := n.Capabilities[0]&0x100 != 0
		observation.Mount.CaseSensitive = &caseSensitive
		if entry.security != "" {
			raw, err := hex.DecodeString(entry.security)
			if err != nil {
				t.Fatal(err)
			}
			ref := mustBlob(t, s, raw)
			entry.record.Darwin.Security = &ref
			observation.Security = authorization.SecurityPresent
		}
		capture.Nodes[entry.name] = observation
	}
	records := map[string]metatransport.Record{".": root, "file": file}
	requestedBytes, err := hex.DecodeString(c.Queried)
	if err != nil {
		t.Fatal(err)
	}
	requested := string(requestedBytes)
	if strings.HasPrefix(c.ID, "symlinks-") {
		count, err := strconv.Atoi(strings.TrimPrefix(c.ID, "symlinks-"))
		if err != nil {
			t.Fatal(err)
		}
		for index := 0; index < count; index++ {
			name := fmt.Sprintf("link%d", index)
			target := fmt.Sprintf("link%d", index+1)
			if index+1 == count {
				target = "file"
			}
			records[name] = metatransport.Record{Original: name, Kind: "symlink", Target: target}
		}
		requested = "link0"
	} else if strings.HasPrefix(c.ID, "expansion-") && c.CreateErr == 0 {
		target, err := hex.DecodeString(c.Target)
		if err != nil {
			t.Fatal(err)
		}
		records["expand"] = metatransport.Record{Original: "expand", Kind: "symlink", Target: string(target)}
	}
	evaluator, err := authorization.New(version, options.Authority)
	if err != nil {
		t.Fatal(err)
	}
	_, _, actual := resolvePath(t.Context(), s, records, capture, evaluator, requested, 1024, osversion.MacOSProfile(version.Major))
	var expected error
	switch c.LookupErr {
	case 0:
	case 2:
		expected = syscall.ENOENT
	case 13:
		expected = syscall.EACCES
	case 20:
		expected = syscall.ENOTDIR
	case 62:
		expected = syscall.ELOOP
	case 63:
		expected = syscall.ENAMETOOLONG
	default:
		t.Fatal("unqualified Darwin errno", c.LookupErr)
	}
	if !errors.Is(actual, expected) {
		t.Fatalf("lookup %q: portable=%v native=%v", c.ID, actual, expected)
	}
}

func verifyNativePathSources(t *testing.T, name string, sources map[string]string, oracle, script string) {
	t.Helper()
	currentFiles := map[string]string{"probe.c": filepath.Join("..", "..", "testdata", "appledouble", "native", oracle), "capture.go": filepath.Join("..", "..", "scripts", script)}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), sources)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	harness, err := captureprovenance.Inventory(referenceSources)
	if err != nil {
		t.Fatal(err)
	}
	if err = captureprovenance.Verify(referenceSources, sources); err != nil {
		t.Fatal(err)
	}
	expectedSourceCount := 15 + len(harness)
	if oracle == "name-lookup.c" {
		expectedSourceCount++
	}
	if len(sources) != expectedSourceCount {
		t.Fatal("source/SDK/AST inventory differs")
	}
	required := []string{"probe.c", "capture.go", "probe", "arm64-apple-macos15.ast.json", "x86_64-apple-macos15.ast.json", "SDK/sys/stat.h", "SDK/sys/mount.h", "SDK/sys/attr.h", "SDK/sys/acl.h", "SDK/sys/fcntl.h", "SDK/sys/resource.h", "SDK/sys/param.h", "XNU/resource_private.h", "XNU/param.h", "XNU/syslimits.h"}
	if oracle == "name-lookup.c" {
		required = append(required, "SDK/dirent.h")
	}
	for _, key := range required {
		if _, ok := sources[key]; !ok {
			t.Fatal("missing native provenance", key)
		}
	}
	// Fresh capture commands retain every artifact; verify actual bytes before
	// accepting a bootstrap observation. Retained fixtures pin these digests.
	if filepath.Base(name) == "capture.json" || filepath.Base(name) == "capture.json.gz" {
		for key, want := range sources {
			artifact, err := os.ReadFile(filepath.Join(filepath.Dir(name), filepath.FromSlash(key)))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(artifact)
			if hex.EncodeToString(sum[:]) != want {
				t.Fatal("native artifact digest mismatch", key)
			}
		}
	}
	for key, value := range sources {
		digest, err := hex.DecodeString(value)
		if err != nil || len(digest) != 32 {
			t.Fatal("invalid source digest", key)
		}
	}
	for _, header := range []string{"resource_private.h", "param.h", "syslimits.h"} {
		compressed, err := os.ReadFile(filepath.Join("..", "..", "testdata", "appledouble", "native", "pathname-authorization-source", "headers", header+".gz"))
		if err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		current, readErr := io.ReadAll(reader)
		if err = errors.Join(readErr, reader.Close()); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(current)
		if sources["XNU/"+header] != hex.EncodeToString(sum[:]) {
			t.Fatal("stale native XNU header capture", header)
		}
	}
	for key, path := range currentFiles {
		current, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(current)
		if sources[key] != hex.EncodeToString(sum[:]) {
			t.Fatal("stale native source capture", key)
		}
	}
}
