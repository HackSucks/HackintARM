package hostdata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func TestReplacementFilesystemNativeCapture(t *testing.T) {
	testReplacementFilesystemNative(t, false)
}

func TestReplacementFilesystemNativeEncoding(t *testing.T) {
	testReplacementFilesystemNative(t, true)
}

// Native-only collection must finish independently of current Go parity.
func testReplacementFilesystemNative(t *testing.T, qualify bool) {
	version, err := osversion.Detect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	nativeProfile, err := osversion.ProfileForMacOS(version)
	if err != nil {
		t.Fatal(err)
	}
	oracle := filepath.Join(t.TempDir(), "oracle")
	source := "../../testdata/appledouble/native/replacement-filesystem.c"
	if output, err := cirunner.Command("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", oracle).CombinedOutput(); err != nil {
		t.Fatalf("compile native metadata copy: %v %s", err, output)
	}
	type observation struct {
		Filesystem, Profile string
		Input, Native       []byte
		Errno               int
	}
	var observed []observation
	for _, filesystem := range []string{"MS-DOS FAT32", "ExFAT"} {
		t.Run(filesystem, func(t *testing.T) {
			mount := replacementTestVolume(t, filesystem)
			for _, size := range []int{0, 1, 3650, 3651, 3652, 4096, 65100, 65400, 65536, 131072} {
				for _, forkSize := range []int{0, 1, 4, 255, 256, 285, 286, 287, 65535, 65536, 65537} {
					profile := fmt.Sprintf("value-%d-fork-%d", size, forkSize)
					t.Run(profile, func(t *testing.T) {
						dir, err := os.MkdirTemp(mount, "copy-")
						if err != nil {
							t.Fatal(err)
						}
						input, target := filepath.Join(dir, "input"), filepath.Join(dir, "target")
						if err = os.WriteFile(input, []byte("data"), 0600); err != nil {
							t.Fatal(err)
						}
						metadata := &appledouble.StreamFile{FinderInfo: [32]byte{1}, Attrs: []appledouble.StreamAttr{
							{Name: "com.example.a", Value: bytes.NewReader(bytes.Repeat([]byte{0xa5}, size))},
							{Name: "com.example.z", Value: bytes.NewReader([]byte("retained"))},
						}}
						// Retain the fixture creator's actual provenance when the native
						// process supplies it; record it as input, never invent its bytes.
						f, err := os.Open(input)
						if err != nil {
							t.Fatal(err)
						}
						provenance, present, readErr := ReadXattr(f, "com.apple.provenance", MaxXattrReadSize)
						if err = f.Close(); err != nil || readErr != nil {
							t.Fatal(err, readErr)
						}
						if present {
							metadata.Attrs = append([]appledouble.StreamAttr{{Name: "com.apple.provenance", Value: bytes.NewReader(provenance)}}, metadata.Attrs...)
						}
						if forkSize != 0 {
							metadata.ResourceFork = bytes.NewReader(bytes.Repeat([]byte{0x6b}, forkSize))
						}
						var packed bytes.Buffer
						if _, err = metadata.EncodeTo(t.Context(), &packed, appledouble.DefaultStreamLimits()); err != nil {
							t.Fatal(err)
						}
						// Use native-valid offsets for empty values. COPYFILE_PACK's zero-offset
						// empty value has a separately qualified absent-namespace interpretation.
						wire := packed.Bytes()
						if size == 0 {
							offset := 120
							if present {
								offset += 32
							}
							copy(wire[offset:offset+4], wire[96:100])
						}
						if err = os.WriteFile(filepath.Join(dir, "._input"), wire, 0600); err != nil {
							t.Fatal(err)
						}
						output, nativeErr := cirunner.Command(oracle, input, target).Output()
						var outcome struct {
							Result      int `json:"result"`
							Errno       int `json:"errno"`
							FreeResult  int `json:"free_result"`
							CloseResult int `json:"close_result"`
						}

						if err = json.Unmarshal(output, &outcome); err != nil {
							t.Fatalf("native copy result: %v %s: %v", nativeErr, output, err)
						}
						if nativeErr != nil {
							t.Fatalf("native oracle invocation: %v %s", nativeErr, output)
						}
						if outcome.FreeResult != 0 || outcome.CloseResult != 0 || !((outcome.Result == 0 && outcome.Errno == 0) || (outcome.Result == -1 && outcome.Errno > 0)) {
							t.Fatalf("invalid native outcome or cleanup: %+v", outcome)
						}
						native, err := os.ReadFile(filepath.Join(dir, "._target"))

						if err != nil {
							t.Fatal(err)
						}
						observed = append(observed, observation{Filesystem: filesystem, Profile: profile, Input: bytes.Clone(wire), Native: native, Errno: outcome.Errno})
						if !qualify {
							return
						}
						wantResult, wantErrno := 0, 0
						if nativeProfile != osversion.MacOS15 && forkSize > 0 && forkSize < 286 {
							wantResult, wantErrno = -1, 22
						}
						if outcome.Result != wantResult || outcome.Errno != wantErrno {
							t.Fatalf("native profile %d changed: %+v; expected result=%d errno=%d", nativeProfile, outcome, wantResult, wantErrno)
						}
						// Compare the held Go copy on every success and failure,
						// including bytes left in the failed private carrier.
						from, e := os.Open(input)
						if e != nil {
							t.Fatal(e)
						}
						defer from.Close()
						to, e := os.OpenFile(filepath.Join(dir, "go"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
						if e != nil {
							t.Fatal(e)
						}
						defer to.Close()
						info, e := from.Stat()
						if e != nil {
							t.Fatal(e)
						}
						var want error
						if outcome.Errno != 0 {
							want = syscall.EINVAL
						}
						if e = copyReplacementMetadataContext(t.Context(), from, to, info); !errors.Is(e, want) {
							t.Fatalf("Go held metadata copy: %v want %v", e, want)
						}
						copied, e := os.ReadFile(filepath.Join(dir, "._go"))
						if e != nil {
							t.Fatal(e)
						}
						if !bytes.Equal(copied, native) {
							t.Fatal("held native copies leave different carrier bytes")
						}
						if outcome.Errno != 0 {
							return
						}
						var encoded bytes.Buffer
						if _, err = metadata.EncodeFilesystemTo(t.Context(), &encoded, appledouble.DefaultStreamLimits()); err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(encoded.Bytes(), native) {
							for i := 0; i < min(len(native), encoded.Len()); i++ {
								if native[i] != encoded.Bytes()[i] {
									t.Logf("first differing offset %d native=%02x encoded=%02x", i, native[i], encoded.Bytes()[i])
									break
								}
							}
							t.Fatalf("fresh filesystem encoding differs: native=%d encoded=%d", len(native), encoded.Len())
						}
					})
				}
			}
		})
	}
	if out := os.Getenv("APFS_REPLACEMENT_FILESYSTEM_CAPTURE"); out != "" {
		data, err := json.MarshalIndent(observed, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(out, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

type replacementFilesystemTestValue struct {
	size int64
	read func([]byte, int64) (int, error)
}

func (v replacementFilesystemTestValue) Size() int64 { return v.size }
func (v replacementFilesystemTestValue) ReadAt(p []byte, off int64) (int, error) {
	return v.read(p, off)
}

func TestReplacementFilesystemForkFailures(t *testing.T) {
	for _, scenario := range []string{"negative-size", "overflow", "empty", "cancel-before", "cancel-read", "short-read", "read-error", "write-error", "cancel-write", "stream"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var positions []uint32
			value := replacementFilesystemTestValue{size: 65537, read: func(p []byte, off int64) (int, error) {
				for i := range p {
					p[i] = byte((off + int64(i)) % 251)
				}
				return len(p), io.EOF
			}}
			write := func(p []byte, off uint32) error {
				positions = append(positions, off)
				for i, b := range p {
					if b != byte((uint64(off)+uint64(i))%251) {
						t.Fatal("corrupt streamed byte")
					}
				}
				return nil
			}
			var want error
			switch scenario {
			case "negative-size":
				value.size = -1
				want = os.ErrInvalid
			case "overflow":
				value.size = 1 << 32
				want = os.ErrInvalid
			case "empty":
				value.size = 0
			case "cancel-before":
				cancel()
				want = context.Canceled
			case "cancel-read":
				value.read = func(p []byte, _ int64) (int, error) { cancel(); return len(p), nil }
				want = context.Canceled
			case "short-read":
				value.read = func([]byte, int64) (int, error) { return 0, io.EOF }
				want = io.ErrUnexpectedEOF
			case "read-error":
				value.read = func(p []byte, _ int64) (int, error) { return len(p), io.ErrClosedPipe }
				want = io.ErrClosedPipe
			case "write-error":
				write = func([]byte, uint32) error { return io.ErrClosedPipe }
				want = io.ErrClosedPipe
			case "cancel-write":
				write = func([]byte, uint32) error { cancel(); return nil }
				want = context.Canceled
			}
			if e := copyReplacementFilesystemForkUsing(ctx, value, write); !errors.Is(e, want) {
				t.Fatalf("got %v want %v", e, want)
			}
			if scenario == "stream" && !slices.Equal(positions, []uint32{0, 65536}) {
				t.Fatal(positions)
			}
		})
	}
}

func TestReplacementFilesystemMetadataFailures(t *testing.T) {
	for _, scenario := range []string{"list", "cancel", "read", "missing", "write", "fork", "success"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var wrote []string
			ops := replacementFilesystemCopyOps{
				list: func() ([]string, error) { return []string{"first", ResourceForkName, "last"}, nil },
				read: func(name string, limit int) ([]byte, bool, error) {
					want := MaxXattrReadSize
					if name == "last" {
						want -= 5
					}
					if limit != want {
						t.Fatal(limit, want)
					}
					return []byte(name), true, nil
				},
				write: func(name string, _ []byte) error { wrote = append(wrote, name); return nil },
				fork:  func() error { return nil },
			}
			var want error
			switch scenario {
			case "list":
				ops.list = func() ([]string, error) { return nil, io.ErrClosedPipe }
				want = io.ErrClosedPipe
			case "cancel":
				cancel()
				want = context.Canceled
			case "read":
				ops.read = func(string, int) ([]byte, bool, error) { return nil, false, io.ErrClosedPipe }
				want = io.ErrClosedPipe
			case "missing":
				ops.read = func(string, int) ([]byte, bool, error) { return nil, false, nil }
				want = ErrXattrChanged
			case "write":
				ops.write = func(string, []byte) error { return io.ErrClosedPipe }
				want = io.ErrClosedPipe
			case "fork":
				ops.fork = func() error { return io.ErrClosedPipe }
				want = io.ErrClosedPipe
			}
			if e := copyReplacementFilesystemMetadataUsing(ctx, ops); !errors.Is(e, want) {
				t.Fatal(e, want)
			}
			if scenario == "fork" || scenario == "success" {
				if !slices.Equal(wrote, []string{"first", "last"}) {
					t.Fatal("later attributes were lost", wrote)
				}
			}
		})
	}
	closed, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err = copyReplacementFilesystemMetadataContext(t.Context(), closed, closed); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}
