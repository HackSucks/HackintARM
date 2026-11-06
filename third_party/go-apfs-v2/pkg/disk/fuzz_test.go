package disk

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The fuzz targets below feed arbitrary bytes to the parsers that read
// untrusted image metadata. They check only that parsing returns (no panic,
// no hang, no runaway allocation); run one with, for example,
//
//	go test ./pkg/disk -run '^$' -fuzz '^FuzzOpenDMG$' -fuzztime 30s

// fuzzLimits keeps legitimate-but-large inputs from slowing the fuzzer down;
// the bounds themselves are what is being exercised.
var fuzzLimits = DMGLimits{MetadataBytes: 256 << 10, ChunkBytes: 1 << 20, ImageBytes: 16 << 20}

// apfsTypeGUID is the Apple_APFS partition type in GPT's mixed-endian layout.
var apfsTypeGUID = gptGUID{
	0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11,
	0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
}

// gptDisk returns a small whole-disk image: a GPT naming one APFS partition
// at LBA 40, followed by that partition's first sectors.
func gptDisk(t testing.TB) []byte {
	t.Helper()
	img := gptImage(t, 128)
	table := make([]GPTPartition, 128)
	table[0] = GPTPartition{Type: apfsTypeGUID, StartingLBA: 40, EndingLBA: 47}
	var buf bytes.Buffer
	buf.Write(img)
	if err := binary.Write(&buf, binary.LittleEndian, table); err != nil {
		t.Fatal(err)
	}
	disk := make([]byte, 48*gptSectorSize)
	copy(disk, buf.Bytes())
	copy(disk[40*gptSectorSize:], "NXSB")
	if off, err := findAPFSPartitionInGPT(bytes.NewReader(disk)); err != nil || off != 40*gptSectorSize {
		t.Fatalf("seed GPT disk does not parse: offset %d, err %v", off, err)
	}
	return disk
}

// dmgSeeds returns small DMGs in every codec the encoder writes, with and
// without a GPT, so the fuzzer starts from well-formed koly, plist, mish and
// chunk structures.
func dmgSeeds(t testing.TB) [][]byte {
	t.Helper()
	disk := gptDisk(t)
	payload := mixedImage(8<<10, 3)
	layouts := [][]SourceBlock{
		{{Name: "disk image", Data: payload}},
		{
			{Name: "Protective Master Boot Record (MBR : 0)", StartSector: 0, Data: disk[:gptSectorSize]},
			{Name: "GPT Header (Primary GPT Header : 1)", StartSector: 1, Data: disk[gptSectorSize : 2*gptSectorSize]},
			{Name: "GPT Partition Data (Primary GPT Table : 2)", StartSector: 2, Data: disk[2*gptSectorSize : 34*gptSectorSize]},
			{Name: "disk image (Apple_APFS : 4)", StartSector: 40, Data: payload},
		},
	}
	var seeds [][]byte
	for _, blocks := range layouts {
		for _, c := range []Compression{CompressionZlib, CompressionLZFSE, CompressionLZMA, CompressionNone} {
			var buf bytes.Buffer
			if err := EncodeUDIF(&buf, blocks, &EncodeOptions{Compression: c, ChunkSectors: 8}); err != nil {
				t.Fatalf("EncodeUDIF: %v", err)
			}
			seeds = append(seeds, buf.Bytes())
		}
	}
	return seeds
}

// FuzzOpenDMG parses a DMG (koly trailer, plist, mish chunk tables, GPT) and
// then reads its file-system partition, decompressing every chunk it covers.
func FuzzOpenDMG(f *testing.F) {
	for _, seed := range dmgSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewDMGReader(bytes.NewReader(data), int64(len(data)), fuzzLimits)
		if err != nil {
			return
		}
		defer r.Close()
		buf := make([]byte, 64<<10)
		for off := int64(0); off < min(r.Size(), 1<<20); off += int64(len(buf)) {
			if _, err := r.ReadAt(buf, off); err != nil {
				return
			}
		}
	})
}

// FuzzFindAPFSPartitionInGPT parses a raw disk's GPT header and table.
func FuzzFindAPFSPartitionInGPT(f *testing.F) {
	f.Add(gptDisk(f))
	f.Add(gptImage(f, 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = findAPFSPartitionInGPT(bytes.NewReader(data))
	})
}

// FuzzFindAPFSPartitionInAPM parses a raw disk's Apple Partition Map.
func FuzzFindAPFSPartitionInAPM(f *testing.F) {
	f.Add(apmImage(f, []struct {
		kind  string
		start uint32
	}{{"Apple_partition_map", 1}, {"Apple_Driver_ATAPI", 32}, {"Apple_HFS", 64}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = findAPFSPartitionInAPM(bytes.NewReader(data))
	})
}

// FuzzDecompressADC decodes an ADC (UDCO) chunk. The first two bytes choose
// the expected output size, as a chunk record would.
func FuzzDecompressADC(f *testing.F) {
	f.Add([]byte{0x00, 0x13, 0x92, 't', 'h', 'e', ' ', 'q', 'u', 'i', 'c', 'k', ' ', 'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x'})
	f.Add([]byte{0x00, 0x04, 0x80, 'a', 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		want := int(binary.BigEndian.Uint16(data))
		_, _ = DecompressADC(data[2:], want)
	})
}
