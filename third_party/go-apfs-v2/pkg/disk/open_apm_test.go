package disk

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// apmImage builds a minimal whole-disk image carrying an Apple Partition Map:
// a driver descriptor at block 0, then one map entry per partition.
func apmImage(t testing.TB, entries []struct {
	kind  string
	start uint32
}) []byte {
	t.Helper()
	img := make([]byte, apmBlockSize*(len(entries)+2))
	binary.BigEndian.PutUint16(img, 0x4552) // 'ER', the driver descriptor

	for i, e := range entries {
		off := apmBlockSize * (i + 1)
		binary.BigEndian.PutUint16(img[off:], apmSignature)
		binary.BigEndian.PutUint32(img[off+4:], uint32(len(entries)))
		binary.BigEndian.PutUint32(img[off+8:], e.start)
		copy(img[off+apmTypeOffset:], e.kind)
	}
	return img
}

func TestFindAPFSPartitionInAPM(t *testing.T) {
	type entry = struct {
		kind  string
		start uint32
	}

	t.Run("picks the file system partition, not the first one", func(t *testing.T) {
		img := apmImage(t, []entry{
			{"Apple_partition_map", 1},
			{"Apple_Driver_ATAPI", 32},
			{"Apple_HFS", 64},
		})
		got, err := findAPFSPartitionInAPM(bytes.NewReader(img))
		if err != nil {
			t.Fatalf("findAPFSPartitionInAPM: %v", err)
		}
		if want := int64(64 * apmBlockSize); got != want {
			t.Errorf("offset = %d, want %d", got, want)
		}
	})

	t.Run("prefers APFS over HFS+", func(t *testing.T) {
		img := apmImage(t, []entry{
			{"Apple_HFS", 64},
			{"Apple_APFS", 512},
		})
		got, err := findAPFSPartitionInAPM(bytes.NewReader(img))
		if err != nil {
			t.Fatalf("findAPFSPartitionInAPM: %v", err)
		}
		if want := int64(512 * apmBlockSize); got != want {
			t.Errorf("offset = %d, want %d: APFS is preferred", got, want)
		}
	})

	t.Run("refuses a map with no file system", func(t *testing.T) {
		img := apmImage(t, []entry{{"Apple_partition_map", 1}})
		if _, err := findAPFSPartitionInAPM(bytes.NewReader(img)); err == nil {
			t.Error("accepted a map holding no file-system partition")
		}
	})

	t.Run("refuses a non-APM image", func(t *testing.T) {
		if _, err := findAPFSPartitionInAPM(bytes.NewReader(make([]byte, 4096))); err == nil {
			t.Error("accepted an image with no partition map")
		}
	})

	t.Run("refuses an absurd entry count", func(t *testing.T) {
		img := apmImage(t, []entry{{"Apple_HFS", 64}})
		binary.BigEndian.PutUint32(img[apmBlockSize+4:], 1<<20)
		if _, err := findAPFSPartitionInAPM(bytes.NewReader(img)); err == nil {
			t.Error("accepted a map claiming a million entries")
		}
	})
}
