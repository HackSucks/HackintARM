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
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// The archive is a real C capture, not a model-generated authorization result.
// APFS_RECOMPRESSION_ACCESS_CAPTURE independently replays fresh CI evidence.
func TestRecompressionAccessNativeEvidence(t *testing.T) {
	paths := []string{
		"../../testdata/appledouble/native/recompression-access-macos15.json.gz",
		"../../testdata/appledouble/native/recompression-access-macos26.json.gz",
		"../../testdata/appledouble/native/recompression-access-macos27.json.gz",
	}
	if fresh := os.Getenv("APFS_RECOMPRESSION_ACCESS_CAPTURE"); fresh != "" {
		paths = append(paths, fresh)
	}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			z, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			var capture struct {
				Schema  int
				Host    string
				Sources map[string]string
				Cases   []struct {
					Scenario, Operation   string
					UID, GID, Mode, Flags uint32
					EffectiveUID          uint32 `json:"effective_uid"`
					Volume                uint32 `json:"volume_flags"`
					UserUUID              string `json:"user_uuid"`
					SecurityInput         string `json:"security_input"`
					Groups                []uint32
					Errno                 int
				}
				OpenCases []json.RawMessage
			}
			if err = json.NewDecoder(z).Decode(&capture); err != nil {
				t.Fatal(err)
			}
			if err = z.Close(); err != nil {
				t.Fatal(err)
			}
			if capture.Schema != 1 || len(capture.Cases) != 168 || len(capture.OpenCases) != 2 {
				t.Fatal("incomplete independent access evidence", len(capture.Cases), len(capture.OpenCases))
			}
			version, err := osversion.Parse(capture.Host)
			referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), capture.Sources)
			if referenceErr != nil {
				t.Fatal(referenceErr)
			}
			if err := captureprovenance.Verify(referenceSources, capture.Sources); err != nil {
				t.Fatal(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			profile, err := osversion.ProfileForMacOS(version)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range []string{"scripts/capture-recompression-access.go", "testdata/appledouble/native/recompression-access.c", "testdata/appledouble/native/recompression-open.c", "testdata/appledouble/native/compression-lz4.json.gz", "testdata/appledouble/native/recompression-access-source/sources.json", "testdata/appledouble/native/recompression-access-source/vfs_subr.c.gz", "testdata/appledouble/native/recompression-access-source/vfs_syscalls.c.gz", "testdata/appledouble/native/recompression-access-source/kern_authorization.c.gz", "testdata/appledouble/native/recompression-access-source/kern_credential.c.gz"} {
				body, err := captureprovenance.ReadSource(referenceSources, capture.Sources, source)
				if err != nil {
					t.Fatal(err)
				}
				if fmt.Sprintf("%x", sha256.Sum256(body)) != capture.Sources[source] {
					t.Fatal("stale native source", source)
				}
			}
			for _, arch := range []string{"arm64", "x86_64"} {
				for _, probe := range []string{"recompression-access", "recompression-open"} {
					if hash := capture.Sources[probe+"."+arch+".ast.json"]; len(hash) != 64 {
						t.Fatal("missing both architecture ASTs", probe, arch)
					}
				}
			}
			seen := map[string]bool{}
			for _, c := range capture.Cases {
				t.Run(c.Scenario+"/"+c.Operation, func(t *testing.T) {
					key := c.Scenario + "/" + c.Operation
					if seen[key] {
						t.Fatal("duplicate native case")
					}
					seen[key] = true
					securityBytes, err := hex.DecodeString(c.SecurityInput)
					if err != nil {
						t.Fatal(err)
					}
					security, err := appledouble.ParseFileSecurity(securityBytes)
					if err != nil {
						t.Fatal(err)
					}
					identity, err := hex.DecodeString(c.UserUUID)
					if err != nil || len(identity) != 16 {
						t.Fatal("invalid identity", err)
					}
					uuid := [16]byte(identity)
					record := metatransport.Record{Darwin: metatransport.DarwinState{UID: &c.UID, GID: &c.GID}}
					access, err := newRecompressionAccess(record, security, &Authority{UID: c.EffectiveUID, Groups: c.Groups, UserUUID: &uuid}, c.Volume)
					if err != nil {
						t.Fatal(err)
					}
					access.profile = profile
					stat := hostdata.StatCopySource{UID: c.UID, GID: c.GID, Mode: c.Mode, Flags: c.Flags}
					err = access.authorize(c.Operation, stat)
					if c.Operation == "chmod" {
						err = access.chmod(stat, 0640)
					}
					want := nativeDarwinError(t, c.Errno)
					if !errors.Is(err, want) {
						t.Fatalf("native errno%d (%v) Go %v; captured %s uid=%d gid=%d groups=%v", c.Errno, want, err, capture.Host, c.UID, c.GID, c.Groups)
					}
				})
			}
		})
	}
}

func TestRecompressionAccessSourceEvidence(t *testing.T) {
	root := "../../testdata/appledouble/native/recompression-access-source"
	raw, err := os.ReadFile(filepath.Join(root, "sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Release string
		Sources []struct{ URL, File, SHA256 string }
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Release != "xnu-11417.140.69" || len(manifest.Sources) != 4 {
		t.Fatal("incomplete pinned Apple policy sources")
	}
	files := map[string]string{"vfs_subr.c.gz": "bsd/vfs/vfs_subr.c", "vfs_syscalls.c.gz": "bsd/vfs/vfs_syscalls.c", "kern_authorization.c.gz": "bsd/kern/kern_authorization.c", "kern_credential.c.gz": "bsd/kern/kern_credential.c"}
	for _, source := range manifest.Sources {
		path, ok := files[source.File]
		if !ok {
			t.Fatal("unexpected source", source.File)
		}
		delete(files, source.File)
		if source.URL != "https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11417.140.69/"+path {
			t.Fatal("unpinned Apple source", source.URL)
		}
		raw, err = os.ReadFile(filepath.Join(root, source.File))
		if err != nil {
			t.Fatal(err)
		}
		z, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(z)
		if err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(body)) != source.SHA256 {
			t.Fatal("Apple body differs", source.File)
		}
		if !bytes.Contains(body, []byte("APPLE_OSREFERENCE_LICENSE_HEADER_START")) {
			t.Fatal("Apple license header missing", source.File)
		}
	}
}

// Native captures retain Darwin errno numbers. syscall.Errno uses a different
// numeric namespace on Windows, so replay translates names rather than numbers
// or receiving-host error strings. Unknown native outcomes need explicit review.
func nativeDarwinError(t *testing.T, errno int) error {
	t.Helper()
	switch errno {
	case 0:
		return nil
	case 1:
		return syscall.EPERM
	case 5:
		return syscall.EIO
	case 13:
		return syscall.EACCES
	case 22:
		return syscall.EINVAL
	case 30:
		return syscall.EROFS
	case 45:
		return syscall.ENOTSUP
	default:
		t.Fatalf("unqualified Darwin errno %d", errno)
		return nil
	}
}
