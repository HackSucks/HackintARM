package apfs_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// The fuzz targets below feed malformed metadata to the APFS reader and check
// only that it returns: no panic, no hang, no runaway allocation. Every input
// has its Fletcher-64 checksum recomputed first, so mutations reach the
// parsers rather than stopping at checksum validation. Run one with, for
// example,
//
//	go test ./pkg/apfs -run '^$' -fuzz '^FuzzOpenImage$' -fuzztime 30s -fuzzminimizetime 1s

const fuzzBlockSize = 4096

type memImage struct{ b []byte }

func (m *memImage) WriteAt(p []byte, off int64) (int, error) {
	if end := int(off) + len(p); end > len(m.b) {
		m.b = append(m.b, make([]byte, end-len(m.b))...)
	}
	copy(m.b[off:], p)
	return len(p), nil
}

var (
	fuzzImageOnce   sync.Once
	fuzzImage       []byte
	fuzzImageBlocks []int // indexes of the image's non-zero blocks
	fuzzImageErr    error
)

// seedImage builds, once, a container whose volume has a 2-level file-system
// tree, a 2-level extentref tree, a nested directory, a symlink, extended
// attributes and a snapshot, and records which of its blocks hold data.
func seedImage(t testing.TB) ([]byte, []int) {
	t.Helper()
	fuzzImageOnce.Do(func() {
		children := []*apfswrite.Entry{
			{Name: "link", Mode: os.ModeSymlink | 0o755, Data: []byte("file000")},
			{Name: "tagged", Data: []byte("tagged\n"), Xattrs: map[string][]byte{"com.example.tag": []byte("value")}},
			{Name: "sub", Mode: os.ModeDir | 0o755, Children: []*apfswrite.Entry{
				{Name: "leaf", Data: []byte("leaf\n")},
			}},
		}
		for i := range 100 {
			children = append(children, &apfswrite.Entry{Name: fmt.Sprintf("file%03d", i), Data: fmt.Appendf(nil, "content %d\n", i)})
		}
		img := &memImage{}
		fuzzImageErr = apfswrite.CreateContainer(img, 0, &apfswrite.CreateOptions{
			VolumeName: "Fuzz",
			Root:       &apfswrite.Entry{Children: children},
			FixedTime:  time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		})
		fuzzImage = img.b
		for i := 0; i+fuzzBlockSize <= len(fuzzImage); i += fuzzBlockSize {
			if !bytes.Equal(fuzzImage[i:i+fuzzBlockSize], make([]byte, fuzzBlockSize)) {
				fuzzImageBlocks = append(fuzzImageBlocks, i/fuzzBlockSize)
			}
		}
	})
	if fuzzImageErr != nil {
		t.Fatalf("CreateContainer: %v", fuzzImageErr)
	}
	return fuzzImage, fuzzImageBlocks
}

// withChecksum returns data padded to a block with a valid object checksum.
func withChecksum(data []byte) []byte {
	block := make([]byte, fuzzBlockSize)
	copy(block, data)
	sum, _ := apfs.CalculateFletcher64(block[8:], 0)
	binary.LittleEndian.PutUint64(block, sum)
	return block
}

// patchedImage serves a base image with one block replaced.
type patchedImage struct {
	base  []byte
	block int64
	patch []byte
}

func (p *patchedImage) ReadAt(buf []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(p.base)) {
		return 0, io.EOF
	}
	n := copy(buf, p.base[off:])
	start, end := p.block*fuzzBlockSize, (p.block+1)*fuzzBlockSize
	if lo, hi := max(off, start), min(off+int64(n), end); lo < hi {
		copy(buf[lo-off:hi-off], p.patch[lo-start:hi-start])
	}
	if n < len(buf) {
		return n, io.EOF
	}
	return n, nil
}

// walkContainer opens every volume and reads what a user of the package
// would: directory listings, file contents, link targets and attributes.
func walkContainer(r io.ReaderAt) {
	container, err := apfs.Open(r, &apfs.OpenOptions{})
	if err != nil {
		return
	}
	volumes, err := container.Volumes()
	if err != nil {
		return
	}
	for _, v := range volumes {
		visited := 0
		_ = fs.WalkDir(v, ".", func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if visited++; visited > 1000 {
				return fs.SkipAll
			}
			_, _ = v.Xattrs(name)
			switch {
			case d.Type()&fs.ModeSymlink != 0:
				_, _ = v.Readlink(name)
			case d.Type().IsRegular():
				if f, err := v.Open(name); err == nil {
					_, _ = io.CopyN(io.Discard, f, 1<<20)
					f.Close()
				}
			}
			return nil
		})
		_, _ = v.NumberOfSnapshots()
	}
}

// FuzzOpenImage replaces one metadata block of a valid container and then
// opens and walks it. The input's first two bytes pick which of the image's
// non-zero blocks to replace; the rest is the new block's contents.
func FuzzOpenImage(f *testing.F) {
	img, blocks := seedImage(f)
	for i, b := range blocks {
		seed := binary.LittleEndian.AppendUint16(nil, uint16(i))
		f.Add(append(seed, img[b*fuzzBlockSize+8:(b+1)*fuzzBlockSize]...))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		which := blocks[int(binary.LittleEndian.Uint16(data))%len(blocks)]
		// The patch omits the checksum field, which is recomputed.
		walkContainer(&patchedImage{
			base:  img,
			block: int64(which),
			patch: withChecksum(append(make([]byte, 8), data[2:]...)),
		})
	})
}

// FuzzBTreeNode parses a single B-tree node.
func FuzzBTreeNode(f *testing.F) {
	img, blocks := seedImage(f)
	for _, b := range blocks {
		f.Add(img[b*fuzzBlockSize : (b+1)*fuzzBlockSize])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = apfs.NewBTreeNode().ReadData(withChecksum(data))
	})
}

// FuzzContainerSuperblock parses a container superblock (nx_superblock_t).
func FuzzContainerSuperblock(f *testing.F) {
	img, _ := seedImage(f)
	f.Add(img[:fuzzBlockSize])
	f.Fuzz(func(t *testing.T, data []byte) {
		csb, _ := apfs.NewContainerSuperblock()
		_ = csb.ReadData(withChecksum(data))
	})
}

// FuzzVolumeSuperblock parses a volume superblock (apfs_superblock_t).
func FuzzVolumeSuperblock(f *testing.F) {
	img, blocks := seedImage(f)
	for _, b := range blocks {
		block := img[b*fuzzBlockSize : (b+1)*fuzzBlockSize]
		if binary.LittleEndian.Uint32(block[24:])&0xffff == 0x0d {
			f.Add(block)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = apfs.NewVolumeSuperblock().ReadData(withChecksum(data), false)
	})
}
