package disk

import (
	"encoding/binary"
	"fmt"
)

// DMGLimits bounds allocations and advertised image extents while reading UDIF.
// Defaults allow 16 MiB of metadata, 64 MiB per encoded/decoded chunk and a 1 TiB
// logical image. ImageBytes bounds extents, not total memory. Callers inspecting
// uploads can choose a smaller logical image limit. All values cap at 1 TiB.
type DMGLimits struct {
	MetadataBytes uint64
	ChunkBytes    uint64
	ImageBytes    uint64
}

func (l DMGLimits) defaults() DMGLimits {
	if l.MetadataBytes == 0 {
		l.MetadataBytes = 16 << 20
	}
	if l.ChunkBytes == 0 {
		l.ChunkBytes = 64 << 20
	}
	if l.ImageBytes == 0 {
		l.ImageBytes = 1 << 40
	}
	l.MetadataBytes = min(l.MetadataBytes, 1<<40)
	l.ChunkBytes = min(l.ChunkBytes, 1<<40)
	l.ImageBytes = min(l.ImageBytes, 1<<40)
	return l
}

// checkLZFSESize checks every block's advertised output before the codec
// allocates. Compressed data is still validated by the codec itself.
func checkLZFSESize(src []byte, limit uint64) error {
	le := binary.LittleEndian
	var total uint64
	for len(src) >= 4 {
		magic := string(src[:4])
		if magic == "bvx$" {
			if total != limit {
				return fmt.Errorf("LZFSE output size differs from chunk")
			}
			return nil
		}
		if len(src) < 8 {
			return fmt.Errorf("truncated LZFSE block")
		}
		n := uint64(le.Uint32(src[4:]))
		if n > limit-total {
			return fmt.Errorf("LZFSE output exceeds chunk")
		}
		total += n
		var header, payload uint64
		switch magic {
		case "bvx-":
			header, payload = 8, n
		case "bvxn":
			if len(src) < 12 {
				return fmt.Errorf("truncated LZVN header")
			}
			header, payload = 12, uint64(le.Uint32(src[8:]))
		case "bvx1":
			if len(src) < 772 {
				return fmt.Errorf("truncated LZFSE V1 header")
			}
			header = 772
			payload = uint64(le.Uint32(src[20:])) + uint64(le.Uint32(src[24:]))
		case "bvx2":
			if len(src) < 32 {
				return fmt.Errorf("truncated LZFSE V2 header")
			}
			header = le.Uint64(src[24:]) & 0xffffffff
			payload = ((le.Uint64(src[8:]) >> 20) & 0xfffff) + ((le.Uint64(src[16:]) >> 40) & 0xfffff)
			if header < 32 {
				return fmt.Errorf("invalid LZFSE V2 header size")
			}
		default:
			return fmt.Errorf("unknown LZFSE block")
		}
		if header > uint64(len(src)) || payload > uint64(len(src))-header {
			return fmt.Errorf("LZFSE block exceeds compressed data")
		}
		src = src[header+payload:]
	}
	return fmt.Errorf("missing LZFSE end marker")
}
