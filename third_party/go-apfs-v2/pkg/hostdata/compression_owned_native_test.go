//go:build darwin

package hostdata

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"golang.org/x/sys/unix"
)

type ownedNativeSnapshot struct {
	Device      int64  `json:"dev"`
	Inode       uint64 `json:"inode"`
	Size        int64  `json:"size"`
	Mode, Flags uint32
	Filesystem  string
	MountFlags  uint32 `json:"mount_flags"`
	Attribute   *string
}
type ownedNativeObservation struct {
	Route, Mutation string
	Compressed      int
	OpenErrno       int `json:"open_errno"`
	ZeroWriteErrno  int `json:"zero_write_errno"`
	Before          ownedNativeSnapshot
	AfterOpen       ownedNativeSnapshot `json:"after_open"`
	AfterClose      ownedNativeSnapshot `json:"after_close"`
	Data            string
}
type ownedNativeCapture struct {
	Schema int
	Cases  []struct {
		Filesystem  string
		Observation ownedNativeObservation
	}
}

func TestNativeCompressionOwnedMounted(t *testing.T) {
	base := os.Getenv("APFS_COMPRESSION_OWNED_MOUNT")
	if base == "" {
		base = t.TempDir()
	}
	captured := os.Getenv("APFS_COMPRESSION_OWNED_CAPTURE")
	var corpus ownedNativeCapture
	if captured != "" {
		b, err := os.ReadFile(captured)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(b, &corpus); err != nil {
			t.Fatal(err)
		}
	} else {
		version, err := osversion.Detect(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join("../../testdata/appledouble/native", "compression-owned-macos"+strconv.FormatUint(uint64(version.Major), 10)+".json.gz")
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
		if err = json.NewDecoder(z).Decode(&corpus); err != nil {
			t.Fatal(err)
		}
	}
	if corpus.Schema != 1 || len(corpus.Cases) != 24 && len(corpus.Cases) != 72 {
		t.Fatal("incomplete native inventory", len(corpus.Cases))
	}
	count := 0
	for _, trial := range corpus.Cases {
		if captured == "" && trial.Filesystem != "host" {
			continue
		}
		c := trial.Observation
		count++
		t.Run(trial.Filesystem+"/"+strconv.Itoa(c.Compressed)+"/"+c.Route+"/"+c.Mutation, func(t *testing.T) {
			parent, err := os.MkdirTemp(base, "owned-go-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(parent)
			name := filepath.Join(parent, "root")
			if err = os.Mkdir(name, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(name)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			data := make([]byte, 32768)
			for i := range data {
				data[i] = byte('A' + i%23)
			}
			created, err := root.OpenFile("file", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
			if err != nil {
				t.Fatal(err)
			}
			if c.Compressed != 1 {
				if _, err = created.Write(data); err != nil {
					t.Fatal(err)
				}
			}
			if c.Before.Attribute != nil {
				attr, e := hex.DecodeString(*c.Before.Attribute)
				if e != nil {
					t.Fatal(e)
				}
				if e = unix.Fsetxattr(int(created.Fd()), DecmpfsName, attr, 0); e != nil {
					t.Fatal(e)
				}
			}
			if err = unix.Fchflags(int(created.Fd()), int(c.Before.Flags)); err != nil {
				t.Fatal(err)
			}
			if err = created.Close(); err != nil {
				t.Fatal(err)
			}
			observer, err := root.Open("file")
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close()
			check := func(want ownedNativeSnapshot) {
				t.Helper()
				var state unix.Stat_t
				if e := unix.Fstat(int(observer.Fd()), &state); e != nil {
					t.Fatal(e)
				}
				if uint32(state.Mode) != want.Mode || state.Flags != want.Flags || state.Size != want.Size {
					t.Fatal("native metadata differs", state, want)
				}
				volume, e := QueryCompressionVolume(t.Context(), observer)
				if e != nil {
					t.Fatal(e)
				}
				if volume.Filesystem != want.Filesystem || captured != "" && volume.Flags != want.MountFlags {
					t.Fatal("native volume differs", volume, want)
				}
				attr, present, e := readVisibleXattr(func(p []byte) (int, error) { return getCaptureXattrFD(int(observer.Fd()), DecmpfsName, p) }, 8192)
				if e != nil {
					t.Fatal(e)
				}
				if present != (want.Attribute != nil) || present && hex.EncodeToString(attr) != *want.Attribute {
					t.Fatal("native attribute differs")
				}
			}
			check(c.Before)
			if c.Mutation == "root-before" {
				if err = os.Rename(name, name+"-moved"); err != nil {
					t.Fatal(err)
				}
			}
			var file *os.File
			if c.Route == "root" {
				file, err = root.OpenFile("file", os.O_RDWR, 0)
			} else {
				file, err = os.OpenFile(filepath.Join(name, "file"), os.O_RDWR, 0)
			}
			if c.OpenErrno != 0 {
				if !errors.Is(err, unix.Errno(c.OpenErrno)) {
					if file != nil {
						file.Close()
					}
					t.Fatal("native acquisition errno differs", err, c.OpenErrno)
				}
				check(c.AfterClose)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			beforeInput := nativeCompressionInput{file: file, ctx: t.Context()}
			before, err := beforeInput.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Seek(19, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			input, err := NewNativeCompressionInput(t.Context(), file)
			if err != nil {
				file.Close()
				t.Fatal(err)
			}
			defer input.Close()
			after, err := input.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("owned binding changed acquisition state", before, after, err)
			}
			position, err := file.Seek(0, io.SeekCurrent)
			if err != nil || position != 19 {
				t.Fatal("binding changed offset", position, err)
			}
			check(c.AfterOpen)
			if c.Mutation == "root-after" {
				if err = os.Rename(name, name+"-moved"); err != nil {
					t.Fatal(err)
				}
			}
			if c.Mutation == "leaf-after" {
				if err = root.Rename("file", "moved"); err != nil {
					t.Fatal(err)
				}
			}
			if err = input.ProbeWrite(); err != nil {
				t.Fatal(err)
			}
			duplicate, err := input.Duplicate()
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(data))
			_, readErr := duplicate.ReadAt(got, 0)
			if err = errors.Join(readErr, duplicate.Close()); err != nil {
				t.Fatal(err)
			}
			expected, err := hex.DecodeString(c.Data)
			if err != nil || !bytes.Equal(got, expected) || !bytes.Equal(got, data) {
				t.Fatal("complete native payload differs", err)
			}
			check(c.AfterClose)
		})
	}
	if count != 24 {
		t.Fatal("incomplete mounted replay", count)
	}
}
