package recompression

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type nativeObjectSnapshot struct {
	Flags     uint32
	Size      int64
	Attribute *string
	Fork      *string
}

func TestRecompressionObjectNativeAcquisition(t *testing.T) {
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
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			z, err := gzip.NewReader(file)
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			var capture struct {
				Host      string
				OpenCases []struct {
					Name                   string
					Type                   uint32
					Attribute, Fork, Plain []byte
					Observation            struct {
						Before     nativeObjectSnapshot
						AfterOpen  nativeObjectSnapshot `json:"after_open"`
						AfterClose nativeObjectSnapshot `json:"after_close"`
						OpenErrno  int                  `json:"open_errno"`
						ReadErrno  int                  `json:"read_errno"`
						Data       *string
					}
				}
			}
			if err = json.NewDecoder(z).Decode(&capture); err != nil {
				t.Fatal(err)
			}
			if len(capture.OpenCases) != 2 {
				t.Fatalf("native acquisition inventory %d", len(capture.OpenCases))
			}
			version, err := osversion.Parse(capture.Host)
			if err != nil {
				t.Fatal(err)
			}
			profile, err := osversion.ProfileForMacOS(version)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range capture.OpenCases {
				t.Run(c.Name, func(t *testing.T) {
					values := storageNativeValues(storageNativeCase{Attribute: c.Attribute, Fork: c.Fork})
					o := objectFixture(t, c.Observation.Before.Flags, 0, values)
					if err := o.data.Truncate(0); err != nil {
						t.Fatal(err)
					}
					if n, err := o.data.WriteAt(c.Plain, 0); n != len(c.Plain) || err != nil {
						t.Fatal(n, err)
					}
					baseline := digest(c.Plain)
					o.baseline = &baseline
					o.access = &recompressionAccess{profile: profile, authority: Authority{UID: 501, Groups: []uint32{20}}}
					assertSnapshot := func(want nativeObjectSnapshot) {
						t.Helper()
						info, err := o.data.Stat()
						if err != nil {
							t.Fatal(err)
						}
						if flags := o.stat().Flags; flags != want.Flags || info.Size() != want.Size {
							t.Fatalf("native inode differs flags%#x/%#x size%d/%d", flags, want.Flags, info.Size(), want.Size)
						}
						for _, attr := range []struct {
							name string
							want *string
						}{{hostdata.DecmpfsName, want.Attribute}, {hostdata.ResourceForkName, want.Fork}} {
							value, present := o.values[attr.name]
							if present != (attr.want != nil) {
								t.Fatalf("native %s presence differs", attr.name)
							}
							if present && hex.EncodeToString(objectValue(t, value)) != *attr.want {
								t.Fatalf("native %s storage differs", attr.name)
							}
						}
					}
					assertSnapshot(c.Observation.Before)
					input, err := o.open(t.Context())
					if !errors.Is(err, nativeDarwinError(t, c.Observation.OpenErrno)) {
						t.Fatalf("native open errno%d, Go%v", c.Observation.OpenErrno, err)
					}
					assertSnapshot(c.Observation.AfterOpen)
					if err != nil {
						if input != nil || o.opened {
							t.Fatal("failed acquisition retained an input lease")
						}
						assertSnapshot(c.Observation.AfterClose)
						return
					}
					defer input.Close()
					stream, err := input.Duplicate()
					if err != nil {
						t.Fatal(err)
					}
					var readback bytes.Buffer
					buffer := make([]byte, 65536)
					for at := int64(0); at < int64(len(c.Plain)); {
						p := buffer[:min(int64(len(buffer)), int64(len(c.Plain))-at)]
						n, err := stream.ReadAt(p, at)
						if n != len(p) || err != nil && !errors.Is(err, io.EOF) {
							t.Fatal("materialized readback failure", n, err)
						}
						readback.Write(p[:n])
						at += int64(n)
					}
					if c.Observation.ReadErrno != 0 || c.Observation.Data == nil || hex.EncodeToString(readback.Bytes()) != *c.Observation.Data || !bytes.Equal(readback.Bytes(), c.Plain) {
						t.Fatal("native logical readback differs")
					}
					if err = stream.Close(); err != nil {
						t.Fatal(err)
					}
					if err = input.Close(); err != nil {
						t.Fatal(err)
					}
					assertSnapshot(c.Observation.AfterClose)
				})
			}
		})
	}
}
