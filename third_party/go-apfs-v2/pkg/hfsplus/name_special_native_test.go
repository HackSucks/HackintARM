package hfsplus

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func TestHFSSpecialNativeEvidence(t *testing.T) {
	paths := []string{}
	expectedMajors := map[string]uint32{}
	for _, major := range []int{15, 26, 27} {
		path := fmt.Sprintf("../../testdata/appledouble/native/hfs-special-names-macos%d.json.gz", major)
		paths = append(paths, path)
		expectedMajors[path] = uint32(major)
	}
	if fresh := os.Getenv("APFS_HFS_SPECIAL_CAPTURE"); fresh != "" {
		paths = append(paths, fresh)
	}
	names := []string{"plain", ".", "..", ".\u200d", "\u200d.", "..\u200d", "\u200d..", "\u200d", "x\u2400y", "\u2400", "x\uffffy", "x%EF%BF%BFy", "x:y"}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("required native HFS special-name profile", err)
			}
			plain, err := decodeSpecialEvidence(raw, expectedMajors[path])
			if err != nil {
				t.Fatal(err)
			}
			var capture struct {
				Schema  int
				Sources map[string]string
				Volumes []struct {
					Kind   string
					Detach []string
					Native struct {
						Count      int
						Filesystem string
						Sensitive  bool `json:"case_sensitive"`
						Cases      []struct {
							ID            string
							Name          string `json:"name_hex"`
							Parent, Inode uint64
							CreateErrno   int    `json:"create_errno"`
							LookupErrno   int    `json:"lookup_errno"`
							LookupInode   uint64 `json:"lookup_inode"`
							Stored        []struct {
								Hex   string
								Inode uint64
							}
						}
					}
					Raw []struct {
						Parent, Inode uint32
						UTF16         []uint16
						Key, Value    string
					}
				}
			}
			if err = json.Unmarshal(plain, &capture); err != nil {
				t.Fatal(err)
			}
			referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), capture.Sources)
			if referenceErr != nil {
				t.Fatal(referenceErr)
			}
			harness, err := captureprovenance.Inventory(referenceSources)
			if err != nil {
				t.Fatal(err)
			}
			if err = captureprovenance.Verify(referenceSources, capture.Sources); err != nil {
				t.Fatal(err)
			}
			if capture.Schema != 1 || len(capture.Volumes) != 2 || len(capture.Sources) != 16+len(harness) {
				t.Fatal("native inventory", len(capture.Sources))
			}
			for _, source := range []string{"testdata/appledouble/native/hfs-special-names.c", "scripts/capture-hfs-special-names.go", "testdata/appledouble/native/name-comparison-source/vfs_utfconv.c.gz", "testdata/appledouble/native/name-comparison-source/sources.json", "go.mod", "go.sum"} {
				b, err := captureprovenance.ReadSource(referenceSources, capture.Sources, source)
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(b)
				if capture.Sources[source] != hex.EncodeToString(hash[:]) {
					t.Fatal("native source provenance", source)
				}
			}
			for _, source := range []string{"native-binary", "arm64.ast.json", "x86_64.ast.json", "SDK/sys/stat.h", "SDK/sys/mount.h", "SDK/sys/attr.h", "SDK/sys/fcntl.h", "SDK/dirent.h", "SDK/unistd.h", "SDK/sys/errno.h"} {
				if path == os.Getenv("APFS_HFS_SPECIAL_CAPTURE") {
					local := source
					if local == "native-binary" {
						local = "probe"
					}
					b, err := os.ReadFile(filepath.Join(filepath.Dir(path), local))
					if err != nil {
						t.Fatal(err)
					}
					hash := sha256.Sum256(b)
					if capture.Sources[source] != hex.EncodeToString(hash[:]) {
						t.Fatal("fresh native evidence hash", source)
					}
				}
				if b, err := hex.DecodeString(capture.Sources[source]); err != nil || len(b) != 32 {
					t.Fatal("missing native compiler evidence", source)
				}
			}
			observed := 0
			for index, volume := range capture.Volumes {
				if volume.Kind != []string{"HFS+", "HFSX"}[index] || volume.Native.Sensitive != (index == 1) || volume.Native.Filesystem != "hfs" || volume.Native.Count != 13 || len(volume.Native.Cases) != 13 || len(volume.Detach) == 0 {
					t.Fatal("native volume inventory")
				}
				for i, c := range volume.Native.Cases {
					if c.ID != fmt.Sprintf("case-%03d", i) || c.Name != hex.EncodeToString([]byte(names[i])) || c.Parent == 0 || c.LookupErrno != 0 {
						t.Fatal("native case inventory")
					}
					var want error
					if c.CreateErrno == 17 {
						want = syscall.EEXIST
					} else if c.CreateErrno != 0 {
						t.Fatal("unqualified native errno", c.CreateErrno)
					}
					if err := validateCreationNames(&Entry{Children: []*Entry{{Name: names[i]}}}, volume.Native.Sensitive); !errors.Is(err, want) {
						t.Fatalf("%s %q: %v want %v", volume.Kind, names[i], err, want)
					}
					observed++
					if want != nil {
						if i != 1 && i != 2 || c.Inode != 0 || len(c.Stored) != 0 {
							t.Fatal("native reserved-component inventory")
						}
						continue
					}
					if c.Inode == 0 || c.LookupInode != c.Inode || len(c.Stored) != 1 || c.Stored[0].Inode != c.Inode {
						t.Fatal("native identity")
					}
					matches := 0
					for _, record := range volume.Raw {
						if uint64(record.Parent) != c.Parent || uint64(record.Inode) != c.Inode {
							continue
						}
						matches++
						key, err := hex.DecodeString(record.Key)
						if err != nil {
							t.Fatal(err)
						}
						value, err := hex.DecodeString(record.Value)
						if err != nil {
							t.Fatal(err)
						}
						if len(key) != 6+2*len(record.UTF16) || len(value) < 12 || binary.BigEndian.Uint16(value) != 2 || binary.BigEndian.Uint32(key) != record.Parent || binary.BigEndian.Uint32(value[8:]) != record.Inode || int(binary.BigEndian.Uint16(key[4:])) != len(record.UTF16) {
							t.Fatal("raw catalog identity")
						}
						for j, u := range record.UTF16 {
							if binary.BigEndian.Uint16(key[6+2*j:]) != u {
								t.Fatal("raw name mismatch")
							}
						}
						actual := string(utf16.Decode(record.UTF16))
						if got := normalizeName(catalogName(names[i])); got != actual {
							t.Fatalf("%s name %x catalog %x native %x", volume.Kind, names[i], got, actual)
						}
						if got := hex.EncodeToString([]byte(posixName(actual))); got != c.Stored[0].Hex {
							t.Fatal("native readdir spelling", got, c.Stored[0].Hex)
						}
					}
					if matches != 1 {
						t.Fatal("missing or duplicate raw catalog entry")
					}
				}
			}
			if observed != 26 {
				t.Fatal("incomplete native observation count", observed)
			}
		})
	}
}

// Decode the complete gzip stream before trusting JSON so both the checksum and
// the native profile are mandatory, including on the fresh CI capture path.
func decodeSpecialEvidence(raw []byte, expected uint32) ([]byte, error) {
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(z)
	if err = errors.Join(err, z.Close()); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	var envelope struct{ Host string }
	if err = decoder.Decode(&envelope); err != nil {
		return nil, err
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing native JSON: %v", err)
	}
	profile, err := osversion.ParseProductVersion(envelope.Host)
	if err != nil {
		return nil, err
	}
	if _, err = osversion.ProfileForMacOS(profile); err != nil {
		return nil, err
	}
	if expected != 0 && profile.Major != expected {
		return nil, fmt.Errorf("native profile%d does not match retained profile%d", profile.Major, expected)
	}
	return plain, nil
}

func TestHFSSpecialNativeEnvelopeRejectsCorruption(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/hfs-special-names-macos27.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decodeSpecialEvidence(raw, 27)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeSpecialEvidence(raw, 15); err == nil {
		t.Fatal("accepted macOS27 evidence as macOS15")
	}
	if _, err = decodeSpecialEvidence(raw[:len(raw)-1], 27); err == nil {
		t.Fatal("accepted truncated gzip checksum")
	}
	corrupted := append([]byte(nil), raw...)
	corrupted[len(corrupted)-8] ^= 1
	if _, err = decodeSpecialEvidence(corrupted, 27); err == nil {
		t.Fatal("accepted corrupt gzip checksum")
	}
	encode := func(data []byte) []byte {
		t.Helper()
		var out bytes.Buffer
		z := gzip.NewWriter(&out)
		if _, err := z.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	if _, err = decodeSpecialEvidence(encode(append(append([]byte(nil), plain...), []byte("{}")...)), 27); err == nil {
		t.Fatal("accepted trailing JSON object")
	}
	if _, err = decodeSpecialEvidence(encode([]byte(`{"Host":"ProductVersion: 14.0"}`)), 0); err == nil {
		t.Fatal("accepted unsupported fresh profile")
	}
	if _, err = decodeSpecialEvidence(encode([]byte(`{"Host":""}`)), 0); err == nil {
		t.Fatal("accepted missing native profile")
	}
}
