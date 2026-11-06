package decmpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzfse"
)

// memSource is a decmpfs Source over a byte slice.
type memSource struct {
	data []byte
}

func (m *memSource) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, bytes.ErrTooLarge
	}
	return copy(p, m.data[off:]), nil
}

func (m *memSource) Size() uint64 { return uint64(len(m.data)) }

// compressiblePattern returns n bytes that compress well.
func compressiblePattern(n int) []byte {
	return bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), n/44+1)[:n]
}

func TestDecompressLZFSERejectsZeroV2Header(t *testing.T) {
	src := make([]byte, 32)
	copy(src, "bvx2")
	out := make([]byte, 128)
	size := len(out)
	if err := Decompress(src, MethodLZFSE, out, &size); !errors.Is(err, lzfse.ErrCorrupt) {
		t.Fatalf("Decompress: %v, want ErrCorrupt", err)
	}
}

// TestDecompressLZFSEEscape covers the leaf decompressor, including the raw
// escape. The escape is signalled by the absence of the LZFSE block magic, not
// by a fixed sentinel: any first byte other than 'b' means "stored raw". Using
// LZVN's 0x06 as a sentinel here would misread every other raw chunk.
func TestDecompressLZFSEEscape(t *testing.T) {
	payload := compressiblePattern(4096)
	compressed, err := lzfse.Compress(payload)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}

	t.Run("compressed round trip", func(t *testing.T) {
		out := make([]byte, len(payload))
		size := len(out)
		if err := decompressLZFSE(compressed, out, &size); err != nil {
			t.Fatalf("decompressLZFSE: %v", err)
		}
		if !bytes.Equal(out[:size], payload) {
			t.Error("round trip through decompressLZFSE changed the data")
		}
	})

	// macOS writes 0xff, but any non-magic first byte must be treated the same.
	for _, marker := range []byte{0xff, 0x00, 0x06, 0x61} {
		t.Run("raw escape marker", func(t *testing.T) {
			raw := append([]byte{marker}, payload...)
			out := make([]byte, len(payload))
			size := len(out)
			if err := decompressLZFSE(raw, out, &size); err != nil {
				t.Fatalf("marker %#02x: %v", marker, err)
			}
			if size != len(payload) || !bytes.Equal(out[:size], payload) {
				t.Errorf("marker %#02x: raw chunk did not round-trip", marker)
			}
		})
	}

	t.Run("rejects bad input without panicking", func(t *testing.T) {
		out := make([]byte, 128)
		for name, input := range map[string][]byte{
			"empty":          {},
			"magic only":     {0x62},
			"truncated bvx2": append([]byte("bvx2"), 1, 2, 3),
			"output exceeds buffer": func() []byte {
				big, _ := lzfse.Compress(compressiblePattern(8192))
				return big
			}(),
		} {
			size := len(out)
			if err := decompressLZFSE(input, out, &size); err == nil {
				t.Errorf("%s: decompressLZFSE succeeded, want an error", name)
			}
		}
	})
}

func TestDecompressLZFSEBoundedAllocation(t *testing.T) {
	compressed, err := lzfse.Compress(make([]byte, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, BlockSize)
	size := BlockSize
	// Keep setup outside the measured interval and do not run in parallel:
	// TotalAlloc measures allocations across this test process.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = Decompress(compressed, MethodLZFSE, out, &size)
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 1<<20 {
		t.Fatalf("Decompress allocated %d bytes, want less than 1 MiB", allocated)
	}
	if !errors.Is(err, lzfse.ErrOutputFull) {
		t.Fatalf("Decompress: %v, want ErrOutputFull", err)
	}
	t.Logf("Decompress allocated %d bytes", after.TotalAlloc-before.TotalAlloc)
}

func TestDecompressLZFSEOutputSize(t *testing.T) {
	payload := compressiblePattern(4096)
	compressed, err := lzfse.Compress(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		size int
	}{
		{"negative", -1},
		{"larger than buffer", len(payload) + 2},
		{"empty", 0},
		{"too small", len(payload) - 1},
		{"exact", len(payload)},
		{"extra room", len(payload) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := bytes.Repeat([]byte{0xa5}, len(payload)+1)
			size := tc.size
			err := Decompress(compressed, MethodLZFSE, out, &size)
			if tc.size < len(payload) || tc.size > len(out) {
				if err == nil {
					t.Fatal("Decompress succeeded with an invalid or insufficient output size")
				}
				if size != tc.size {
					t.Fatalf("size changed on error: got %d, want %d", size, tc.size)
				}
			} else if err != nil || size != len(payload) || !bytes.Equal(out[:size], payload) {
				t.Fatalf("round trip failed: size=%d, err=%v", size, err)
			}
			if tc.size >= 0 && tc.size <= len(out) {
				for _, b := range out[tc.size:] {
					if b != 0xa5 {
						t.Fatal("Decompress wrote beyond the caller's output size")
					}
				}
			}
		})
	}
}

// TestZlibResourceForkManyBlocksIsAnError guards the descriptor-table read: a
// zlib resource fork needs 8 bytes per block, so a file over roughly 510 MB has
// more descriptors than the fixed 65537-byte segment scratch holds. That used
// to fault on a slice bound instead of returning an error.
func TestZlibResourceForkManyBlocksIsAnError(t *testing.T) {
	// 8 bytes per descriptor from offset 272 overruns the 65537-byte segment
	// scratch past roughly 8159 blocks.
	const blocks = 20000

	// A zlib resource fork: big-endian 0x100 header offset, block count at 260,
	// descriptors from 264. The first descriptor must be *valid*, or the loader
	// rejects it before ever reaching the bulk descriptor read — which is where
	// the fault was.
	fork := make([]byte, 4096)
	binary.BigEndian.PutUint32(fork[0:4], 0x00000100)
	binary.LittleEndian.PutUint32(fork[260:264], blocks)
	binary.LittleEndian.PutUint32(fork[264:268], 0x200) // first block offset
	binary.LittleEndian.PutUint32(fork[268:272], 0x100) // its length

	handle, err := NewHandle(&memSource{data: fork}, blocks*BlockSize, MethodDeflate)
	if err != nil {
		t.Fatalf("NewHandle: %v", err)
	}

	// Must return an error, and must not fault with a slice-bounds panic.
	if err := handle.loadCompressedBlockOffsets(); err == nil {
		t.Fatalf("a resource fork claiming %d blocks was accepted", blocks)
	}
}

// TestMethodFor pins the decmpfs type mapping, including the types that are
// recognized but deliberately refused.
func TestMethodFor(t *testing.T) {
	supported := map[uint32]int{
		1: MethodNone,
		9: MethodRawMarked, 10: MethodRawMarked, 13: MethodLZBITMAP, 14: MethodLZBITMAP,
		3:  MethodDeflate,
		4:  MethodDeflate,
		7:  MethodLZVN,
		8:  MethodLZVN,
		11: MethodLZFSE,
		12: MethodLZFSE,
	}
	for decmpfsType, want := range supported {
		got, err := MethodFor(decmpfsType)
		if err != nil {
			t.Errorf("type %d: %v", decmpfsType, err)
			continue
		}
		if got != want {
			t.Errorf("type %d mapped to method %d, want %d", decmpfsType, got, want)
		}
	}

	// Type 5 is the one that used to be decoded, as sparse, and answered with
	// zeros. It is not a compression method at all -- Apple's copyfile.c calls
	// it de-duplication within the generation store -- so the content is not
	// described by this attribute and zeros were simply the wrong answer.
	if _, err := MethodFor(5); err == nil {
		t.Error("decmpfs type 5 was accepted; it must be refused, not decoded as sparse")
	} else if !strings.Contains(err.Error(), "de-duplication") {
		t.Errorf("type 5: error %q does not say what type 5 actually is", err)
	}

	if _, err := MethodFor(99); err == nil {
		t.Error("an unknown decmpfs type was accepted")
	}
}

// TestNewHandleRejectsUndecodableMethods checks that a handle cannot be built
// for a method with no decoder behind it -- including MethodUnknown5, which is
// retained only as a deprecated alias.
func TestNewHandleRejectsUndecodableMethods(t *testing.T) {
	for _, method := range []int{MethodUnknown5, 42} {
		if _, err := NewHandle(&memSource{data: []byte("fpmc")}, 64, method); err == nil {
			t.Errorf("method %d was accepted, want a refusal", method)
		}
	}

	for _, method := range []int{MethodRawMarked, MethodLZBITMAP, MethodDeflate, MethodLZVN, MethodLZFSE} {
		if _, err := NewHandle(&memSource{data: []byte("fpmc")}, 64, method); err != nil {
			t.Errorf("method %d was refused: %v", method, err)
		}
	}
}

// TestCheckInline covers the invariant that inline decoding needs the whole
// attribute value, header included.
func TestCheckInline(t *testing.T) {
	payload := compressiblePattern(64)
	attr := append(append([]byte{}, HeaderSignature[:]...), make([]byte, HeaderSize-4)...)
	attr = append(attr, payload...)

	if err := CheckInline(attr); err != nil {
		t.Errorf("a whole attribute value was rejected: %v", err)
	}

	for name, value := range map[string][]byte{
		"header only":      attr[:HeaderSize],
		"empty":            {},
		"payload stripped": attr[HeaderSize:],
	} {
		if err := CheckInline(value); err == nil {
			t.Errorf("%s: accepted, want a refusal", name)
		}
	}
}
