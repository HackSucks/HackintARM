package hostdata

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestQueryCompressionHeldNativeCorpus(t *testing.T) {
	f, e := os.Open("../../testdata/appledouble/native/compression-query.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct {
		Cases []struct {
			Filesystem, Name              string
			Flags                         uint32
			Attribute, Fork               []byte
			MissingAttribute, MissingFork bool
			Observation                   struct {
				Held struct {
					Result, Errno int
					Bytes         string
					Guard         bool
				} `json:"initial_held_query"`
			}
		}
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if len(corpus.Cases) != 676 {
		t.Fatal("incomplete native metadata inventory")
	}
	base := os.Getenv("APFS_COMPRESSION_MOUNT")
	if base == "" {
		base = t.TempDir()
	}
	for _, c := range corpus.Cases {
		t.Run(fmt.Sprintf("%s/%d/%s", c.Filesystem, c.Flags, c.Name), func(t *testing.T) {
			file, e := os.CreateTemp(base, "held-compression-query-")
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				if e := file.Close(); e != nil {
					t.Error(e)
				}
				if e := os.Remove(file.Name()); e != nil {
					t.Error(e)
				}
			}()
			for _, v := range []struct {
				name   string
				data   []byte
				absent bool
			}{{DecmpfsName, c.Attribute, c.MissingAttribute}, {ResourceForkName, c.Fork, c.MissingFork}} {
				if !v.absent {
					if e = unix.Fsetxattr(int(file.Fd()), v.name, v.data, 0); e != nil {
						t.Fatal(e)
					}
				}
			}
			if e = unix.Fchflags(int(file.Fd()), int(c.Flags)); e != nil {
				t.Fatal(e)
			}
			// The source is already held: malformed compressed data need not be opened
			// again, decoded, or made valid merely to inspect its metadata.
			got, e := QueryCompression(t.Context(), file, len(c.Attribute))
			if e != nil {
				t.Fatal(e)
			}
			var wire [32]byte
			binary.LittleEndian.PutUint32(wire[:4], got.Type)
			binary.LittleEndian.PutUint32(wire[4:8], got.Overhead)
			binary.LittleEndian.PutUint64(wire[8:16], got.StoredSize)
			binary.LittleEndian.PutUint64(wire[16:24], got.LogicalSize)
			copy(wire[24:], got.AttributeExtension[:])
			if c.Observation.Held.Result != 0 || !c.Observation.Held.Guard || c.Observation.Held.Bytes != hex.EncodeToString(wire[:]) {
				t.Fatalf("native metadata differs: got %x, want %+v", wire, c.Observation.Held)
			}
			if got.MissingResourceFork != (c.Observation.Held.Errno == 93) {
				t.Fatal("missing fork differs")
			}
		})
	}
}

func TestCompressionMetadataHeldLargeFork(t *testing.T) {
	file, e := os.CreateTemp(t.TempDir(), "large-query-")
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	fork, e := OpenResourceFork(file, true)
	if e != nil {
		t.Fatal(e)
	}
	size := int64(1<<32) + 1
	if e = fork.Truncate(size); e != nil {
		t.Fatal(e)
	}
	if e = fork.Close(); e != nil {
		t.Fatal(e)
	}
	header := compressionMetadataHeader(8)
	if e = unix.Fsetxattr(int(file.Fd()), DecmpfsName, header, 0); e != nil {
		t.Fatal(e)
	}
	if e = unix.Fchflags(int(file.Fd()), int(UFCompressed)); e != nil {
		t.Fatal(e)
	}
	got, e := QueryCompression(t.Context(), file, len(header))
	if e != nil {
		t.Fatal(e)
	}
	if got.StoredSize != uint64(size)+24 || got.Type != 8 || got.LogicalSize != 65536 {
		t.Fatal(got)
	}
	if _, e = QueryCompression(t.Context(), file, len(header)-1); !errors.Is(e, ErrXattrTooLarge) {
		t.Fatal("attribute budget ignored", e)
	}
	// A rename does not redirect either the metadata or volume query.
	original := file.Name()
	if e = os.Rename(original, filepath.Join(filepath.Dir(original), "renamed")); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(original, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	after, e := QueryCompression(t.Context(), file, len(header))
	if e != nil || after != got {
		t.Fatal(after, e)
	}
	var native unix.Statfs_t
	if e = unix.Fstatfs(int(file.Fd()), &native); e != nil {
		t.Fatal(e)
	}
	flags, e := CompressionVolumeFlags(t.Context(), file)
	if e != nil || flags != native.Flags {
		t.Fatal(flags, native.Flags, e)
	}
	if _, e = file.Stat(); e != nil {
		t.Fatal("metadata capture closed caller handle", e)
	}
}

func TestCompressionMetadataNativeErrors(t *testing.T) {
	if _, _, e := compressionStatUsing(7, func(fd int, state *unix.Stat_t) error {
		if fd != 7 {
			t.Fatal(fd)
		}
		state.Size = -1
		return nil
	}); !errors.Is(e, os.ErrInvalid) {
		t.Fatal("negative native size converted to unsigned extent", e)
	}
	if _, _, e := nativeCompressionStat(-1); !errors.Is(e, syscall.EBADF) {
		t.Fatal(e)
	}
	if _, e := nativeCompressionVolumeFlags(-1); !errors.Is(e, syscall.EBADF) {
		t.Fatal(e)
	}
	f, e := os.CreateTemp(t.TempDir(), "query-errors-")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e = QueryCompression(ctx, f, 0); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	conn, e := f.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	closed := conn.Control(func(uintptr) { t.Fatal("closed descriptor became available") })
	if closed == nil {
		t.Fatal("closed descriptor control succeeded")
	}
	if _, e = QueryCompression(t.Context(), f, 0); !errors.Is(e, closed) {
		t.Fatal(e)
	}
	if _, e = CompressionVolumeFlags(t.Context(), f); !errors.Is(e, closed) {
		t.Fatal(e)
	}
}
