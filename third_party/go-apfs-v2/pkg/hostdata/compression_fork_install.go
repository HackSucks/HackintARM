package hostdata

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"

	internal "github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

// CompressionForkWriter is an already-open, identity-bound native or foreign
// resource fork. InstallCompressionFork takes ownership of closing this writer.
// Its data handle and the privately staged input remain caller-owned.
type CompressionForkWriter interface {
	io.WriterAt
	Sync() error
	Close() error
}

// CompressionForkResult reports the attempted installation, including ignored
// native sync/close failures. Complete means all storage frames were written;
// it does not promise durability. Declined means an independent fork prevented
// installation. BytesWritten includes a short final write.
type CompressionForkResult struct {
	Declined     bool
	Complete     bool
	BytesWritten int64
	Failures     []StatCopyFailure
}

// InstallCompressionFork copies freshly encoded native-policy storage from a
// private stage using the native write boundaries: the complete index, each
// encoded block, then the zlib resource map. It always synchronizes and closes
// the supplied fork, even for inline storage and after write failure. Native
// sync/close failures are recorded but do not prevent the following commit.
// Cancellation and read/write errors stop copying, leave partial fork bytes,
// and still close the writer. No truncation or rollback is performed.
//
// The caller must exclude concurrent mutation. existingForkSize is the observed
// fork length: inline output preserves an independent fork; fork output declines
// when this length is nonzero, without writing any frames. Storage must come from decmpfs.Encode,
// whose native policy bounds logical input to 512 MiB. This stage validates
// frame layout, not compressed payload integrity. It retains at most 65,800
// index bytes and one 65,537-byte block. CommitCompression is the next stage.
func InstallCompressionFork(ctx context.Context, storage decmpfs.EncodedFile, stage io.ReaderAt, existingForkSize int64, fork CompressionForkWriter) (result CompressionForkResult, err error) {
	if fork == nil {
		return result, fs.ErrInvalid
	}
	defer finishCompressionFork(fork, &result)
	if existingForkSize < 0 {
		return result, fs.ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	index, kind, blocks, err := compressionForkIndex(ctx, storage, stage)
	if err != nil {
		return result, err
	}
	if len(index) == 0 {
		result.Complete = true
		return result, nil
	}
	if existingForkSize != 0 {
		result.Declined = true
		return result, nil
	}
	write := func(b []byte, offset int64) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		n, e := fork.WriteAt(b, offset)
		if n < 0 || n > len(b) {
			return errors.Join(io.ErrShortWrite, e)
		}
		result.BytesWritten += int64(n)
		if n != len(b) {
			e = errors.Join(io.ErrShortWrite, e)
		}
		return errors.Join(e, ctx.Err())
	}
	if err = write(index, 0); err != nil {
		return result, err
	}
	buffer := make([]byte, 65537)
	for block := 0; block < blocks; block++ {
		start, end := compressionForkBlock(index, kind, block)
		b := buffer[:end-start]
		if err = readCompressionStage(ctx, stage, b, start); err != nil {
			return result, err
		}
		if err = write(b, start); err != nil {
			return result, err
		}
	}
	if kind == 4 {
		b := buffer[:50]
		if err = readCompressionStage(ctx, stage, b, storage.ForkSize-50); err != nil {
			return result, err
		}
		if err = write(b, storage.ForkSize-50); err != nil {
			return result, err
		}
	}
	result.Complete = true
	return result, nil
}

func readCompressionStage(ctx context.Context, stage io.ReaderAt, data []byte, offset int64) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	n, e := stage.ReadAt(data, offset)
	if n != len(data) {
		return errors.Join(io.ErrUnexpectedEOF, e, ctx.Err())
	}
	if e != nil && !errors.Is(e, io.EOF) {
		return errors.Join(e, ctx.Err())
	}
	return ctx.Err()
}

func compressionForkIndex(ctx context.Context, storage decmpfs.EncodedFile, stage io.ReaderAt) ([]byte, uint32, int, error) {
	invalid := func() ([]byte, uint32, int, error) { return nil, 0, 0, fs.ErrInvalid }
	if storage.ForkSize < 0 {
		return invalid()
	}
	if e := internal.ValidateLayout(storage.Attribute, uint64(len(storage.Attribute)), 0, uint64(storage.ForkSize)); e != nil {
		return nil, 0, 0, e
	}
	kind := binary.LittleEndian.Uint32(storage.Attribute[4:8])
	size := binary.LittleEndian.Uint64(storage.Attribute[8:16])
	if size == 0 || size > 512<<20 || !(kind == 3 || kind == 4 || kind >= 7 && kind <= 14) {
		return invalid()
	}
	if kind&1 != 0 {
		if storage.ForkSize != 0 {
			return invalid()
		}
		return nil, kind, 0, nil
	}
	if stage == nil {
		return invalid()
	}
	blocks := int((size + 65535) / 65536)
	indexSize := (blocks + 1) * 4
	trailer := int64(0)
	if kind == 4 {
		indexSize = 264 + blocks*8
		trailer = 50
	}
	if storage.ForkSize < int64(indexSize)+int64(blocks)+trailer {
		return invalid()
	}
	index := make([]byte, indexSize)
	if e := readCompressionStage(ctx, stage, index, 0); e != nil {
		return nil, 0, 0, e
	}
	if kind == 4 && (binary.BigEndian.Uint32(index[:4]) != 256 || int64(binary.BigEndian.Uint32(index[4:8])) != storage.ForkSize-50 || int64(binary.BigEndian.Uint32(index[8:12])) != storage.ForkSize-306 || binary.BigEndian.Uint32(index[12:16]) != 50 || int64(binary.BigEndian.Uint32(index[256:260])) != storage.ForkSize-310 || binary.LittleEndian.Uint32(index[260:264]) != uint32(blocks)) {
		return invalid()
	}
	end := int64(indexSize)
	for block := 0; block < blocks; block++ {
		start, next := compressionForkBlock(index, kind, block)
		if start != end || next <= start || next-start > 65537 || next > storage.ForkSize-trailer {
			return invalid()
		}
		end = next
	}
	if end != storage.ForkSize-trailer {
		return invalid()
	}
	return index, kind, blocks, nil
}

func compressionForkBlock(index []byte, kind uint32, block int) (int64, int64) {
	if kind == 4 {
		p := index[264+8*block:]
		start := int64(binary.LittleEndian.Uint32(p)) + 260
		return start, start + int64(binary.LittleEndian.Uint32(p[4:]))
	}
	p := index[4*block:]
	return int64(binary.LittleEndian.Uint32(p)), int64(binary.LittleEndian.Uint32(p[4:]))
}
