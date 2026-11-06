package hostdata

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCompressionPathDeniedContent(t *testing.T) {
	oracle := compressionPathOracle(t)
	for _, profile := range []string{"ordinary", "read", "read,write", "readextattr"} {
		t.Run(profile, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			header := compressionMetadataHeader(3)
			if err := unix.Fsetxattr(int(file.Fd()), DecmpfsName, header, 0); err != nil {
				t.Fatal(err)
			}
			if err := unix.Fchflags(int(file.Fd()), int(UFCompressed)); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if profile != "ordinary" {
				out, err := cirunner.CommandContext(t.Context(), "/bin/chmod", "+a", "everyone deny "+profile, path).CombinedOutput()
				if err != nil {
					t.Fatalf("ACL: %v %s", err, out)
				}
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
					defer cancel()
					out, err := cirunner.CommandContext(ctx, "/bin/chmod", "-N", path).CombinedOutput()
					if err != nil {
						t.Errorf("ACL cleanup: %v %s", err, out)
					}
				})
			}
			if profile == "read" || profile == "read,write" {
				f, err := os.Open(path)
				if err == nil {
					f.Close()
					t.Fatal("read control did not fail")
				}
			}
			expected, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			output, oracleErr := cirunner.CommandContext(t.Context(), oracle, path).CombinedOutput()
			if oracleErr != nil {
				t.Fatalf("native query: %v: %s", oracleErr, output)
			}
			t.Logf("native query %s: %s", profile, output)
			var native struct {
				Query struct {
					Result, Errno int
					Bytes         string
					Guard         bool
				} `json:"path_query"`
				FlagsUnchanged    bool `json:"flags_unchanged"`
				SizeUnchanged     bool `json:"size_unchanged"`
				IdentityUnchanged bool `json:"identity_unchanged"`
			}
			if err := json.Unmarshal(output, &native); err != nil {
				t.Fatal(err)
			}
			if !native.Query.Guard || !native.FlagsUnchanged || !native.SizeUnchanged || !native.IdentityUnchanged {
				t.Fatal("native query changed source or exceeded ABI", native)
			}
			got, err := QueryCompressionNoFollow(t.Context(), path, expected, len(header))
			if profile == "readextattr" {
				if !errors.Is(err, os.ErrPermission) || native.Query.Result != -1 || native.Query.Errno != int(unix.EACCES) {
					t.Fatal("xattr access was not denied", err)
				}
				return
			}
			if err != nil || got.Type != 3 || got.StoredSize != uint64(len(header)) {
				t.Fatal(got, err)
			}
			var wire [32]byte
			binary.LittleEndian.PutUint32(wire[:4], got.Type)
			binary.LittleEndian.PutUint32(wire[4:8], got.Overhead)
			binary.LittleEndian.PutUint64(wire[8:16], got.StoredSize)
			binary.LittleEndian.PutUint64(wire[16:24], got.LogicalSize)
			copy(wire[24:], got.AttributeExtension[:])
			if native.Query.Result != 0 || native.Query.Bytes != hex.EncodeToString(wire[:]) {
				t.Fatal("native query bytes differ", native.Query, got)
			}

			raw := make([]byte, len(header))
			n, err := darwinGetXattrPath(path, DecmpfsName, raw, xattrCompressionFlags)
			if err != nil || !bytes.Equal(raw[:n], header) {
				t.Fatal("query changed compression", err)
			}
			var state unix.Stat_t
			if err := unix.Lstat(path, &state); err != nil || state.Flags&UFCompressed == 0 {
				t.Fatal("query cleared compression", err)
			}
			if _, err := QueryCompressionNoFollow(t.Context(), path+"missing", expected, 24); !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		})
	}
}
