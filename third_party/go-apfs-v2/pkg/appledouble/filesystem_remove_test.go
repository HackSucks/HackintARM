package appledouble

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
	"strings"
	"testing"
)

type removalTestFile struct {
	*os.File
	size int64
}

func (f removalTestFile) Size() int64 { return f.size }

// These are byte-for-byte VFS results, including slack and unrelated records,
// from real FAT volumes. Filesystem association and authorization are tested by
// hostdata; this test exercises only regular, decodable AppleDouble carriers.
func TestFilesystemRemovalNativeBytes(t *testing.T) {
	for _, major := range []int{15, 26, 27} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			path := fmt.Sprintf("../../testdata/appledouble/native/metadata-filesystem-macos%d.json.gz", major)
			fresh := os.Getenv("APFS_METADATA_FILESYSTEM_PRODUCERS")
			if fresh != "" {
				path = filepath.Join(fresh, fmt.Sprintf("filesystem-metadata-macos%d", major), "native.json")
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var reader io.Reader = f
			if fresh == "" {
				z, e := gzip.NewReader(f)
				if e != nil {
					t.Fatal(e)
				}
				defer z.Close()
				reader = z
			}
			type entry struct {
				Mode  uint32
				Bytes []byte
			}
			var corpus struct {
				Complete bool
				Cases    []struct {
					ID            string
					Before, After map[string]entry
					Observation   struct{ Result, Errno int }
				}
			}
			if err = json.NewDecoder(reader).Decode(&corpus); err != nil {
				t.Fatal(err)
			}
			if !corpus.Complete || len(corpus.Cases) != 960 {
				t.Fatal("incomplete native producer")
			}
			tested := 0
			for _, c := range corpus.Cases {
				parts := strings.Split(c.ID, "/")
				if len(parts) != 4 || (parts[0] != "ExFAT" && parts[0] != "MS-DOS FAT32") {
					continue
				}
				name := map[string]string{"remove": "com.example.phase2", "remove-finder": FinderInfoName, "remove-fork": ResourceForkName}[parts[3]]
				if name == "" {
					continue
				}
				before, ok := c.Before["._input"]
				if !ok || !os.FileMode(before.Mode).IsRegular() {
					continue
				}
				if _, err := DecodeStream(context.Background(), bytes.NewReader(before.Bytes), DefaultStreamLimits()); err != nil {
					continue
				}
				tested++
				t.Run(c.ID, func(t *testing.T) {
					file, e := os.CreateTemp(t.TempDir(), "carrier")
					if e != nil {
						t.Fatal(e)
					}
					defer file.Close()
					if _, e = file.Write(before.Bytes); e != nil {
						t.Fatal(e)
					}
					result, e := RemoveFilesystemAttribute(context.Background(), removalTestFile{file, int64(len(before.Bytes))}, name)
					if e != nil {
						t.Fatal(e)
					}
					if result.Removed != (c.Observation.Result == 0) || (c.Observation.Result != 0 && c.Observation.Errno != 93) {
						t.Fatalf("result %+v; native result=%d errno=%d", result, c.Observation.Result, c.Observation.Errno)
					}
					after, exists := c.After["._input"]
					if result.Empty == exists {
						t.Fatalf("unlink=%v; native exists=%v", result.Empty, exists)
					}
					if result.Empty {
						return
					}
					actual, e := os.ReadFile(file.Name())
					if e != nil {
						t.Fatal(e)
					}
					if !bytes.Equal(actual, after.Bytes) {
						t.Fatalf("native bytes differ:\nwant %x\n got %x", after.Bytes, actual)
					}
				})
			}
			if tested != 60 {
				t.Fatalf("lost removal codec cases: got %d, want 60", tested)
			}
		})
	}
}

// memoryAttributeFile models short writes, cancellation and partial IO without
// disguising these fault-injection tests as native filesystem observations.
type memoryAttributeFile struct {
	data     []byte
	read     func([]byte, int64) (int, error)
	write    func([]byte, int64) (int, error)
	truncate func(int64) error
}

func (f *memoryAttributeFile) Size() int64 { return int64(len(f.data)) }
func (f *memoryAttributeFile) ReadAt(b []byte, off int64) (int, error) {
	if f.read != nil {
		return f.read(b, off)
	}
	return bytes.NewReader(f.data).ReadAt(b, off)
}
func (f *memoryAttributeFile) WriteAt(b []byte, off int64) (int, error) {
	if f.write != nil {
		return f.write(b, off)
	}
	end := int(off) + len(b)
	if end > len(f.data) {
		f.data = append(f.data, make([]byte, end-len(f.data))...)
	}
	return copy(f.data[int(off):], b), nil
}
func (f *memoryAttributeFile) Truncate(n int64) error {
	if f.truncate != nil {
		return f.truncate(n)
	}
	f.data = f.data[:n]
	return nil
}
func removalBytes(t *testing.T, size int) []byte {
	t.Helper()
	f := &File{FinderInfo: [32]byte{1}, ResourceFork: []byte("fork"), Attrs: []Attr{
		{Name: "first", Value: bytes.Repeat([]byte{1}, size)},
		{Name: "middle", Value: bytes.Repeat([]byte{2}, size)},
		{Name: "last", Value: bytes.Repeat([]byte{3}, size)},
	}}
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestFilesystemRemovalStreaming(t *testing.T) {
	for _, size := range []int{1, 65536, 131073} {
		for _, name := range []string{"first", "middle", "last", FinderInfoName, ResourceForkName} {
			t.Run(fmt.Sprintf("%d/%s", size, name), func(t *testing.T) {
				raw := removalBytes(t, size)
				f := &memoryAttributeFile{data: bytes.Clone(raw)}
				result, err := RemoveFilesystemAttribute(context.Background(), f, name)
				if err != nil || !result.Removed || result.Empty {
					t.Fatal(result, err)
				}
				decoded, err := Decode(f.data)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				want := expected.Xattrs()
				delete(want, name)
				equalAttributes(t, decoded.Xattrs(), want)
				if name != ResourceForkName && len(f.data) != len(raw) {
					t.Fatal("unexpected truncation")
				}
			})
		}
	}
}
func TestFilesystemRemovalFailures(t *testing.T) {
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := RemoveFilesystemAttribute(canceled, &memoryAttributeFile{}, "first"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := RemoveFilesystemAttribute(ctx, &memoryAttributeFile{}, "first"); !errors.Is(err, ErrNotAppleDouble) {
		t.Fatal(err)
	}
	for _, size := range []int{1, 65536} {
		for _, name := range []string{"first", "middle", "last", FinderInfoName, ResourceForkName} {
			t.Run(fmt.Sprintf("%d/%s", size, name), func(t *testing.T) {
				f := &memoryAttributeFile{data: removalBytes(t, size)}
				f.write = func([]byte, int64) (int, error) { return 0, io.ErrClosedPipe }
				if result, err := RemoveFilesystemAttribute(ctx, f, name); !errors.Is(err, io.ErrClosedPipe) || result.Removed {
					t.Fatal(result, err)
				}
			})
		}
	}
	f := &memoryAttributeFile{data: removalBytes(t, 1), truncate: func(int64) error { return io.ErrClosedPipe }}
	if _, err := RemoveFilesystemAttribute(ctx, f, ResourceForkName); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	f = &memoryAttributeFile{data: removalBytes(t, 1), write: func([]byte, int64) (int, error) { return 0, nil }}
	if _, err := RemoveFilesystemAttribute(ctx, f, FinderInfoName); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	for _, name := range []string{FinderInfoName, ResourceForkName, "absent"} {
		raw, err := (&File{Attrs: []Attr{{Name: "only", Value: []byte("data")}}}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		f = &memoryAttributeFile{data: raw}
		if result, err := RemoveFilesystemAttribute(ctx, f, name); err != nil || result.Removed || !bytes.Equal(f.data, raw) {
			t.Fatal(result, err)
		}
	}
	raw, err := (&File{Attrs: []Attr{{Name: "only", Value: []byte("data")}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	f = &memoryAttributeFile{data: raw}
	if result, err := RemoveFilesystemAttribute(ctx, f, "only"); err != nil || !result.Empty || !result.Removed || !bytes.Equal(f.data, raw) {
		t.Fatal(result, err)
	}
}

func TestFilesystemRemovalReadAndRangeFailures(t *testing.T) {
	ctx := context.Background()
	for _, field := range []int{96, 100, 120} {
		f := &memoryAttributeFile{data: removalBytes(t, 1)}
		binary.BigEndian.PutUint32(f.data[field:], 0xffffffff)
		original := bytes.Clone(f.data)
		if result, err := RemoveFilesystemAttribute(ctx, f, "first"); err == nil || result.Removed || !bytes.Equal(f.data, original) {
			t.Fatal(field, result, err)
		}
	}
	// COPYFILE_PACK's empty-value offset is zero, unlike VFS's packed data
	// spans. Reject this mutation layout before writing instead of underflowing
	// a native-style shift. Its read-only decoding remains supported.
	f := &memoryAttributeFile{data: removalBytes(t, 0)}
	before := bytes.Clone(f.data)
	if result, err := RemoveFilesystemAttribute(ctx, f, "first"); err == nil || result.Removed || !bytes.Equal(before, f.data) {
		t.Fatal(result, err)
	}
	for _, size := range []int{1, 65536} {
		f = &memoryAttributeFile{data: removalBytes(t, size)}
		reads := 0
		f.read = func(b []byte, off int64) (int, error) {
			reads++
			if (size == 1 && reads == 2) || (size == 65536 && off > 0) {
				return 0, io.ErrClosedPipe
			}
			return bytes.NewReader(f.data).ReadAt(b, off)
		}
		if result, err := RemoveFilesystemAttribute(ctx, f, "middle"); !errors.Is(err, io.ErrClosedPipe) || result.Removed {
			t.Fatal(size, result, err)
		}
	}
	raw, err := (&File{FinderInfo: [32]byte{1}, ResourceFork: make([]byte, 286)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	f = &memoryAttributeFile{data: raw}
	f.read = func(b []byte, off int64) (int, error) {
		if off > 0 {
			return 0, io.ErrClosedPipe
		}
		return bytes.NewReader(raw).ReadAt(b, off)
	}
	if _, err := RemoveFilesystemAttribute(ctx, f, ResourceForkName); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := filesystemWrite(canceled, f, nil, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestFilesystemRemovalBlankFork(t *testing.T) {
	blank := make([]byte, 286)
	copy(blank[16:], "This resource fork intentionally left blank   \x00")
	ctx := context.Background()
	if visible, err := FilesystemForkVisible(ctx, bytes.NewReader(blank)); err != nil || visible {
		t.Fatal(visible, err)
	}
	blank[16] = 'X'
	if visible, err := FilesystemForkVisible(ctx, bytes.NewReader(blank)); err != nil || !visible {
		t.Fatal(visible, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := FilesystemForkVisible(canceled, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzFilesystemRemoval(f *testing.F) {
	raw, _ := (&File{FinderInfo: [32]byte{1}, ResourceFork: []byte("fork"), Attrs: []Attr{{Name: "attribute", Value: []byte("value")}}}).Encode()
	f.Add(raw, "attribute")
	f.Add(raw, FinderInfoName)
	f.Add(raw, ResourceForkName)
	f.Fuzz(func(t *testing.T, raw []byte, name string) {
		if len(raw) > 1<<20 {
			return
		}
		file := &memoryAttributeFile{data: bytes.Clone(raw)}
		result, err := RemoveFilesystemAttribute(context.Background(), file, name)
		if err != nil || !result.Removed || result.Empty {
			return
		}
		if _, err = DecodeStream(context.Background(), bytes.NewReader(file.data), DefaultStreamLimits()); err != nil {
			t.Fatal("successful removal produced invalid carrier", err)
		}
	})
}

func TestFilesystemRemovalCompactHeader(t *testing.T) {
	raw, err := (&File{FinderInfo: [32]byte{1}, ResourceFork: []byte("fork")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw = append(bytes.Clone(raw[:82]), []byte("fork")...)
	binary.BigEndian.PutUint32(raw[34:38], 32)
	binary.BigEndian.PutUint32(raw[42:46], 82)
	f := &memoryAttributeFile{data: raw}
	result, err := RemoveFilesystemAttribute(context.Background(), f, ResourceForkName)
	if err != nil || !result.Removed || result.Empty {
		t.Fatal(result, err)
	}
	decoded, err := Decode(f.data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.FinderInfo != [32]byte{1} || len(decoded.ResourceFork) != 0 {
		t.Fatal("compact header lost FinderInfo or retained fork")
	}
}
