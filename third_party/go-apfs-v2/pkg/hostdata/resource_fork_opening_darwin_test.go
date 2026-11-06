package hostdata

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"golang.org/x/sys/unix"
)

func TestCompressionResourceForkOpeningNative(t *testing.T) {
	version, err := osversion.Detect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := osversion.ProfileForMacOS(version)
	if err != nil {
		t.Fatal(err)
	}
	corpus := loadNativeForkCorpus(t, profile)
	base := os.Getenv("APFS_COMPRESSION_MOUNT")
	if base == "" {
		base = t.TempDir()
	}
	var volume unix.Statfs_t
	if err = unix.Statfs(base, &volume); err != nil {
		t.Fatal(err)
	}
	filesystem := os.Getenv("APFS_COMPRESSION_FILESYSTEM")
	if filesystem == "" {
		filesystem = "host"
	}
	kind := unix.ByteSliceToString(volume.Fstypename[:])
	if filesystem != "host" && filesystem != "APFS" && filesystem != "HFS+" || filesystem == "APFS" && kind != "apfs" || filesystem == "HFS+" && kind != "hfs" {
		t.Fatal("unqualified native resource-fork volume role", filesystem, kind)
	}
	method := "openat"
	if profile == osversion.MacOS15 {
		method = "getpath"
	}
	count := 0
	for _, c := range corpus.Cases {
		if c.Filesystem != filesystem || c.Method != method {
			continue
		}
		count++
		t.Run(c.State+"/"+c.Access, func(t *testing.T) {
			dir, err := os.MkdirTemp(base, "fork-route-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			name, moved := filepath.Join(dir, "file"), filepath.Join(dir, "moved")
			file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err = file.Write([]byte("DATA")); err != nil {
				t.Fatal(err)
			}
			if c.State != "empty" {
				if err = SetXattr(file, ResourceForkName, []byte("ORIGINAL")); err != nil {
					t.Fatal(err)
				}
			}
			before, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if c.State == "renamed" || c.State == "replaced" || c.State == "unlinked" {
				if err = os.Rename(name, moved); err != nil {
					t.Fatal(err)
				}
			}
			if c.State == "replaced" || c.State == "unlinked" {
				if err = os.WriteFile(name, []byte("SHADOW"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if c.State == "unlinked" {
				if err = os.Remove(moved); err != nil {
					t.Fatal(err)
				}
			}
			got := nativeForkObservation{ReadBytes: -1, WriteBytes: -1, RetainedSize: -1, ShadowUnchanged: true}
			fork, err := OpenResourceFork(file, c.Access == "write")
			if err != nil {
				got.OpenErrno = nativeForkErrno(t, err)
			} else {
				stat, err := fork.Stat()
				if err != nil {
					t.Fatal(err)
				}
				got.Identity = os.SameFile(before, stat)
				var b [16]byte
				n, err := fork.ReadAt(b[:], 0)
				got.ReadBytes = n
				got.ReadHex = hex.EncodeToString(b[:n])
				if err != nil && !errors.Is(err, io.EOF) {
					got.ReadErrno = nativeForkErrno(t, err)
				}
				if c.Access == "write" && got.Identity {
					n, err = fork.WriteAt([]byte("NEW"), 0)
					got.WriteBytes = n
					if err != nil {
						got.WriteErrno = nativeForkErrno(t, err)
					}
				}
				if err = fork.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var data [8]byte
			n, err := file.ReadAt(data[:], 0)
			got.DataUnchanged = n == 4 && bytes.Equal(data[:n], []byte("DATA")) && (err == nil || errors.Is(err, io.EOF))
			retained, present, err := ReadXattr(file, ResourceForkName, 32)
			if err != nil {
				t.Fatal(err)
			}
			if present {
				got.RetainedSize = len(retained)
				got.RetainedHex = hex.EncodeToString(retained)
			} else {
				got.RetainedErrno = int(unix.ENOATTR)
			}
			if c.State == "replaced" || c.State == "unlinked" {
				shadow, err := os.Open(name)
				if err != nil {
					t.Fatal(err)
				}
				b, readErr := io.ReadAll(shadow)
				_, present, xattrErr := ReadXattr(shadow, ResourceForkName, 32)
				closeErr := shadow.Close()
				got.ShadowUnchanged = readErr == nil && xattrErr == nil && closeErr == nil && !present && bytes.Equal(b, []byte("SHADOW"))
			}
			if !reflect.DeepEqual(got, c.Observation) {
				t.Fatalf("macOS %s resource-fork behavior differs: Go %+v native %+v", version, got, c.Observation)
			}
		})
	}
	if count != 10 {
		t.Fatal("incomplete native resource-fork route controls", fmt.Sprint(profile), count)
	}
}
func nativeForkErrno(t *testing.T, err error) int {
	t.Helper()
	var code syscall.Errno
	if !errors.As(err, &code) {
		t.Fatal("non-native error", err)
	}
	return int(code)
}
