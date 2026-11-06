package hostdata

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type nativeForkObservation struct {
	OpenErrno       int    `json:"open_errno"`
	PreflightErrno  int    `json:"preflight_errno"`
	Identity        bool   `json:"identity"`
	ReadBytes       int    `json:"read_bytes"`
	ReadErrno       int    `json:"read_errno"`
	ReadHex         string `json:"read_hex"`
	WriteBytes      int    `json:"write_bytes"`
	WriteErrno      int    `json:"write_errno"`
	RetainedSize    int    `json:"retained_size"`
	RetainedErrno   int    `json:"retained_errno"`
	RetainedHex     string `json:"retained_hex"`
	DataUnchanged   bool   `json:"data_unchanged"`
	ShadowUnchanged bool   `json:"shadow_unchanged"`
}
type nativeForkCase struct {
	Filesystem, Method, State, Access string
	Observation                       nativeForkObservation
}
type nativeForkCorpus struct {
	Schema              int
	Host, Compiler, SDK string
	Sources             map[string]string
	Cases               []nativeForkCase
}

func loadNativeForkCorpus(t *testing.T, profile osversion.MacOSProfile) nativeForkCorpus {
	t.Helper()
	name := fmt.Sprintf("../../testdata/appledouble/native/resource-fork-open-macos%d.json.gz", profile)
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var corpus nativeForkCorpus
	if err = json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	version, err := osversion.ParseProductVersion(corpus.Host)
	if err != nil {
		t.Fatal(err)
	}
	got, err := osversion.ProfileForMacOS(version)
	if err != nil || got != profile || corpus.Schema != 1 || len(corpus.Cases) != 180 || !strings.Contains(corpus.Compiler, "clang") || corpus.SDK == "" {
		t.Fatal("incomplete native resource-fork profile", profile, version, err)
	}
	return corpus
}
func TestCompressionResourceForkProvenance(t *testing.T) {
	for _, profile := range []osversion.MacOSProfile{osversion.MacOS15, osversion.MacOS26, osversion.MacOS27} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			corpus := loadNativeForkCorpus(t, profile)
			referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), corpus.Sources)
			if referenceErr != nil {
				t.Fatal(referenceErr)
			}
			if err := captureprovenance.Verify(referenceSources, corpus.Sources); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"testdata/appledouble/native/resource-fork-open.c", "scripts/capture-resource-fork-open.go", "pkg/osversion/version.go", "pkg/osversion/macos.go", "go.mod", "go.sum"} {
				b, err := captureprovenance.ReadSource(referenceSources, corpus.Sources, name)
				if err != nil {
					t.Fatal(err)
				}
				if fmt.Sprintf("%x", sha256.Sum256(b)) != corpus.Sources[name] {
					t.Fatal("stale native resource-fork source", name)
				}
			}
			for _, arch := range []string{"arm64", "x86_64"} {
				if len(corpus.Sources[arch+"-resource-fork-open.c.ast.json"]) != 64 {
					t.Fatal("missing native resource-fork AST", arch)
				}
			}
			for _, header := range []string{"sys/fcntl.h", "sys/stat.h", "sys/mount.h", "sys/xattr.h"} {
				found := false
				for name, hash := range corpus.Sources {
					if strings.HasSuffix(name, "/usr/include/"+header) && len(hash) == 64 {
						found = true
					}
				}
				if !found {
					t.Fatal("missing native header", header)
				}
			}
			inventory := map[string]bool{}
			for _, filesystem := range []string{"host", "APFS", "HFS+"} {
				for _, method := range []string{"path", "openat", "openfrom", "devfd", "volfs", "getpath"} {
					for _, state := range []string{"live", "renamed", "replaced", "unlinked", "empty"} {
						for _, access := range []string{"read", "write"} {
							inventory[filesystem+"/"+method+"/"+state+"/"+access] = true
						}
					}
				}
			}
			for _, c := range corpus.Cases {
				key := c.Filesystem + "/" + c.Method + "/" + c.State + "/" + c.Access
				if !inventory[key] {
					t.Fatal("duplicate or unqualified native case", key)
				}
				delete(inventory, key)
				if !c.Observation.DataUnchanged || !c.Observation.ShadowUnchanged {
					t.Fatal("native probe changed unrelated data", key)
				}
				if c.Observation.OpenErrno == 0 && !c.Observation.Identity {
					t.Fatal("native stream inode mismatch", key)
				}
			}
			if len(inventory) != 0 {
				t.Fatal("missing native resource-fork cases", inventory)
			}
		})
	}
}
