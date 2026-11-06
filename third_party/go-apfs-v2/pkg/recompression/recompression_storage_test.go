package recompression

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type storageNativeCase struct {
	Name, Filesystem       string
	Type                   uint32
	Plain, Attribute, Fork []byte
	Exit                   int
}

func storageNativeValues(c storageNativeCase) map[string]appledouble.Value {
	values := map[string]appledouble.Value{hostdata.DecmpfsName: bytes.NewReader(c.Attribute)}
	if c.Fork != nil {
		values[hostdata.ResourceForkName] = bytes.NewReader(c.Fork)
	}
	return values
}
func readStorageCorpus(t *testing.T, name string) (cases []storageNativeCase) {
	t.Helper()
	file, e := os.Open(filepath.Join("../../testdata/appledouble/native", name))
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	z, e := gzip.NewReader(file)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct{ Cases, Kernel []storageNativeCase }
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.Kernel != nil {
		return corpus.Kernel
	}
	return corpus.Cases
}
func TestCarrierRecompressionStorageNativeFormats(t *testing.T) {
	cases := readStorageCorpus(t, "decmpfs-formats.json.gz")
	if len(cases) != 14 {
		t.Fatalf("native format inventory %d", len(cases))
	}
	seen := map[uint32]bool{}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			seen[c.Type] = true
			if e := validateRecompressionStorage(context.Background(), storageNativeValues(c), digest(c.Plain)); e != nil {
				t.Fatal(e)
			}
		})
	}
	for _, kind := range []uint32{1, 9, 10, 13, 14} {
		if !seen[kind] {
			t.Fatalf("native compression type %d absent", kind)
		}
	}
}
func TestCarrierRecompressionStorageNativeLZ4(t *testing.T) {
	qualified := readStorageCorpus(t, "compression-lz4.json.gz")
	older := readStorageCorpus(t, "compression-lz4-macos26.json.gz")
	if len(qualified) != 1172 || len(older) != 1172 {
		t.Fatalf("native LZ4 inventories %d/%d", len(qualified), len(older))
	}
	for i, c := range qualified {
		t.Run(c.Filesystem+"/"+c.Name, func(t *testing.T) {
			prior := older[i]
			// The decoder validates storage bytes independently of the requested OS.
			// macOS 26 rejects this entire codec; macOS 27 qualifies its byte grammar.
			// Preserve both observations, without treating old-kernel rejection as
			// proof that otherwise valid encoded data is corrupt.
			if prior.Exit != 2 || prior.Name != c.Name || prior.Filesystem != c.Filesystem || prior.Type != c.Type || !bytes.Equal(prior.Plain, c.Plain) || !bytes.Equal(prior.Attribute, c.Attribute) || !bytes.Equal(prior.Fork, c.Fork) {
				t.Fatal("native LZ4 version evidence changed")
			}
			err := validateRecompressionStorage(context.Background(), storageNativeValues(c), digest(c.Plain))
			if (err == nil) != (c.Exit == 0) {
				t.Fatalf("macOS 27 kernel exit %d, validation %v", c.Exit, err)
			}
		})
	}
}
func TestCarrierRecompressionStorageNativePolicy(t *testing.T) {
	file, err := os.Open("../../testdata/appledouble/native/compression-policy.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var corpus struct {
		Cases []struct {
			Filesystem, Requested, Inline, Pattern, Family string
			Size, RandomTail                               int64
			Attribute, Fork                                []byte
			LogicalSHA256                                  string
			After                                          struct {
				Flags    uint32
				Size     int64
				Accepted bool
			}
		}
	}
	if err := json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 4632 {
		t.Fatalf("native policy inventory %d", len(corpus.Cases))
	}
	seen := map[uint32]bool{}
	active := 0
	for _, c := range corpus.Cases {
		if !c.After.Accepted || c.After.Size != c.Size || (c.After.Flags&32 != 0) != (len(c.Attribute) != 0) {
			t.Fatal("inconsistent native policy outcome")
		}
		if len(c.Attribute) == 0 {
			continue
		}
		active++
		t.Run(fmt.Sprintf("%s/%s/%s/%s/%s/%d/%d", c.Filesystem, c.Requested, c.Inline, c.Family, c.Pattern, c.Size, c.RandomTail), func(t *testing.T) {
			seen[binary.LittleEndian.Uint32(c.Attribute[4:])] = true
			values := storageNativeValues(storageNativeCase{Attribute: c.Attribute, Fork: c.Fork})
			if err := validateRecompressionStorage(context.Background(), values, metatransport.BlobRef{SHA256: c.LogicalSHA256, Size: c.Size}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if active != 902 {
		t.Fatalf("native active storage count %d", active)
	}
	for _, kind := range []uint32{3, 4, 7, 8, 10, 11, 12, 13, 14} {
		if !seen[kind] {
			t.Fatalf("missing native compression type %d", kind)
		}
	}
}
func encodedStorageFixture(t *testing.T, kind uint32, plain []byte) (map[string]appledouble.Value, metatransport.BlobRef) {
	t.Helper()
	file, e := os.Create(filepath.Join(t.TempDir(), "fork"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { file.Close() })
	result, e := decmpfs.EncodeFork(context.Background(), bytes.NewReader(plain), int64(len(plain)), kind, file)
	if e != nil {
		t.Fatal(e)
	}
	return map[string]appledouble.Value{hostdata.DecmpfsName: bytes.NewReader(result.Attribute[:]), hostdata.ResourceForkName: io.NewSectionReader(file, 0, result.Size)}, digest(plain)
}

type storageObservedValue struct {
	appledouble.Value
	maximum int
	read    func([]byte, int64) (int, error)
}

func (v *storageObservedValue) ReadAt(p []byte, at int64) (int, error) {
	v.maximum = max(v.maximum, len(p))
	if v.read != nil {
		return v.read(p, at)
	}
	return v.Value.ReadAt(p, at)
}
func TestCarrierRecompressionStorageBoundedBlocks(t *testing.T) {
	plain := bytes.Repeat([]byte("each block remains distinguishable and bounded"), 4000)
	for at := 0; at < len(plain); at += 65536 {
		plain[at] = byte(at / 65536)
	}
	for _, kind := range []uint32{3, 7, 9, 11, 13} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			values, baseline := encodedStorageFixture(t, kind, plain)
			observed := &storageObservedValue{Value: values[hostdata.ResourceForkName]}
			values[hostdata.ResourceForkName] = observed
			if e := validateRecompressionStorage(context.Background(), values, baseline); e != nil {
				t.Fatal(e)
			}
			if observed.maximum <= 0 || observed.maximum > 65537 {
				t.Fatalf("unbounded source read %d", observed.maximum)
			}
			bad := baseline
			bad.SHA256 = digest([]byte("different")).SHA256
			if e := validateRecompressionStorage(context.Background(), values, bad); !errors.Is(e, metatransport.ErrCorrupt) {
				t.Fatal("baseline hash mismatch accepted", e)
			}
		})
	}
}
func storageRaw(plain []byte) []byte {
	p := make([]byte, 16+len(plain))
	copy(p, "fpmc")
	binary.LittleEndian.PutUint32(p[4:], 1)
	binary.LittleEndian.PutUint64(p[8:], uint64(len(plain)))
	copy(p[16:], plain)
	return p
}
func TestCarrierRecompressionStorageFailures(t *testing.T) {
	plain := []byte("baseline")
	for _, tc := range []struct {
		name string
		attr []byte
	}{
		{"missing", nil}, {"short", []byte("fpmc")}, {"signature", bytes.Repeat([]byte{0}, 17)},
		{"unknown type", func() []byte { p := storageRaw(plain); binary.LittleEndian.PutUint32(p[4:], 99); return p }()},
		{"wrong size", storageRaw([]byte("wrong"))},
		{"missing body", storageRaw(plain)[:16]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]appledouble.Value{}
			if tc.attr != nil {
				values[hostdata.DecmpfsName] = bytes.NewReader(tc.attr)
			}
			if e := validateRecompressionStorage(context.Background(), values, digest(plain)); e == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
	t.Run("missing fork", func(t *testing.T) {
		values, baseline := encodedStorageFixture(t, 8, bytes.Repeat(plain, 9000))
		delete(values, hostdata.ResourceForkName)
		if e := validateRecompressionStorage(context.Background(), values, baseline); e == nil {
			t.Fatal("missing fork accepted")
		}
	})
	for _, kind := range []uint32{4, 8, 10, 12, 14} {
		t.Run(fmt.Sprintf("corrupt index %d", kind), func(t *testing.T) {
			values, baseline := encodedStorageFixture(t, kind, bytes.Repeat(plain, 9000))
			values[hostdata.ResourceForkName] = bytes.NewReader([]byte{0xff, 0, 1, 2, 3})
			if e := validateRecompressionStorage(context.Background(), values, baseline); e == nil {
				t.Fatal("corrupt index accepted")
			}
		})
	}
	t.Run("body error retained", func(t *testing.T) {
		sentinel := errors.New("storage read failure")
		values, baseline := encodedStorageFixture(t, 8, bytes.Repeat(plain, 9000))
		values[hostdata.ResourceForkName] = &storageObservedValue{Value: values[hostdata.ResourceForkName], read: func([]byte, int64) (int, error) { return 0, sentinel }}
		if e := validateRecompressionStorage(context.Background(), values, baseline); !errors.Is(e, sentinel) {
			t.Fatal("lost source failure", e)
		}
	})
	for _, name := range []string{"short second header", "error second header", "changed header", "raw validator error"} {
		t.Run(name, func(t *testing.T) {
			base := bytes.NewReader(storageRaw(plain))
			calls := 0
			sentinel := errors.New("injected header read")
			value := &storageObservedValue{Value: base, read: func(p []byte, at int64) (int, error) {
				calls++
				if name == "short second header" && calls == 2 {
					return 1, nil
				}
				if name == "error second header" && calls == 2 {
					return len(p), sentinel
				}
				if name == "changed header" && calls == 2 {
					clear(p)
					return len(p), nil
				}
				if name == "raw validator error" && calls == 3 {
					return 0, sentinel
				}
				return base.ReadAt(p, at)
			}}
			e := validateRecompressionStorage(context.Background(), map[string]appledouble.Value{hostdata.DecmpfsName: value}, digest(plain))
			if e == nil {
				t.Fatal("unstable or failing source accepted")
			}
			if name == "error second header" && !errors.Is(e, sentinel) {
				t.Fatal("lost header error", e)
			}
		})
	}
}
func TestCarrierRecompressionStorageCancellationAndEOF(t *testing.T) {
	for _, plain := range [][]byte{nil, []byte("payload")} {
		t.Run(fmt.Sprintf("size-%d", len(plain)), func(t *testing.T) {
			base := bytes.NewReader(storageRaw(plain))
			value := &storageObservedValue{Value: base, read: func(p []byte, at int64) (int, error) {
				n, e := base.ReadAt(p, at)
				if n == len(p) {
					return n, io.EOF
				}
				return n, e
			}}
			values := map[string]appledouble.Value{hostdata.DecmpfsName: value}
			if e := validateRecompressionStorage(context.Background(), values, digest(plain)); e != nil {
				t.Fatal("full read with EOF rejected", e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if e := validateRecompressionStorage(ctx, values, digest(plain)); !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
		})
	}
	t.Run("cancel during source read", func(t *testing.T) {
		plain := bytes.Repeat([]byte("cancel after first block"), 9000)
		values, baseline := encodedStorageFixture(t, 8, plain)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		base := values[hostdata.ResourceForkName]
		values[hostdata.ResourceForkName] = &storageObservedValue{Value: base, read: func(p []byte, at int64) (int, error) { n, e := base.ReadAt(p, at); cancel(); return n, e }}
		if e := validateRecompressionStorage(ctx, values, baseline); !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	})
}

type storageSizedValue struct {
	appledouble.Value
	size int64
}

func (v storageSizedValue) Size() int64 { return v.size }
func TestCarrierRecompressionStorageSecurity(t *testing.T) {
	for _, count := range []int{-1, 0, 1, 128} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			original := &appledouble.FileSecurity{OwnerUUID: [16]byte{1}, GroupUUID: [16]byte{2}, Trailing: []byte("opaque trailing bytes do not authorize access")}
			if count >= 0 {
				original.ACL = &appledouble.ACL{Entries: make([]appledouble.ACLEntry, count)}
				for i := range original.ACL.Entries {
					original.ACL.Entries[i] = appledouble.ACLEntry{Principal: [16]byte{byte(i + 1)}, Flags: 1, Rights: 2}
				}
			} else {
				original.NoACLFlags = [4]byte{1, 2, 3, 4}
			}
			encoded, e := original.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			base := bytes.NewReader(encoded)
			observed := &storageObservedValue{Value: storageSizedValue{Value: base, size: 1 << 40}, read: func(p []byte, at int64) (int, error) {
				n, e := base.ReadAt(p, at)
				if n == len(p) {
					return n, io.EOF
				}
				return n, e
			}}
			got, e := readRecompressionSecurity(observed)
			if e != nil {
				t.Fatal(e)
			}
			if got.OwnerUUID != original.OwnerUUID || got.GroupUUID != original.GroupUUID || got.NoACLFlags != original.NoACLFlags || len(got.Trailing) != 0 {
				t.Fatalf("security extent changed %#v", got)
			}
			if count < 0 {
				if got.ACL != nil {
					t.Fatal("NOACL became empty ACL")
				}
			} else {
				if got.ACL == nil || len(got.ACL.Entries) != count {
					t.Fatal("ACL entries missing")
				}
				for i, entry := range got.ACL.Entries {
					if entry != original.ACL.Entries[i] {
						t.Fatal("ACL entry changed")
					}
				}
			}
			if observed.maximum != 44+24*max(count, 0) {
				t.Fatalf("read past declared ACL extent %d", observed.maximum)
			}
			if !bytes.Equal(encoded[len(encoded)-len(original.Trailing):], original.Trailing) {
				t.Fatal("opaque original storage changed")
			}
		})
	}
}
func TestCarrierRecompressionStorageSecurityFailures(t *testing.T) {
	original := &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 2}}}}
	encoded, e := original.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"short header", encoded[:43]},
		{"short entries", encoded[:44]},
		{"excess entries", func() []byte { p := bytes.Clone(encoded); binary.BigEndian.PutUint32(p[36:], 129); return p }()},
		{"bad magic", func() []byte { p := bytes.Clone(encoded); p[0] = 255; return p }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := readRecompressionSecurity(bytes.NewReader(tc.data)); !errors.Is(e, appledouble.ErrFileSecurity) {
				t.Fatal(e)
			}
		})
	}
	sentinel := errors.New("security source fault")
	for _, failureCall := range []int{1, 2} {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("read-%d-short-%v", failureCall, short), func(t *testing.T) {
				calls := 0
				base := bytes.NewReader(encoded)
				value := &storageObservedValue{Value: base, read: func(p []byte, at int64) (int, error) {
					calls++
					if calls == failureCall {
						if short {
							return len(p) - 1, nil
						}
						return len(p), sentinel
					}
					return base.ReadAt(p, at)
				}}
				_, e := readRecompressionSecurity(value)
				if !errors.Is(e, io.ErrUnexpectedEOF) || !short && !errors.Is(e, sentinel) {
					t.Fatal("lost security read failure", e)
				}
			})
		}
	}
}
