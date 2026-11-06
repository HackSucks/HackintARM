package appledouble

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
)

// Value is a sized, randomly readable metadata value. The caller owns its
// lifetime and must keep its size and bytes unchanged while it is in use.
// Neither the codec nor a decoded value closes the source. bytes.Reader and
// io.SectionReader implement Value without copying their contents.
type Value interface {
	io.ReaderAt
	Size() int64
}

// StreamAttr retains one ordered ATTR record. A nil Value is an empty value.
type StreamAttr struct {
	Name  string
	Value Value
}

// StreamFile is an AppleDouble snapshot with borrowed values. DecodeStream
// retains wire record order, including duplicates and special names. Encoding
// sorts a copy stably by name, just as File.Encode does, without changing Attrs.
// FinderInfo is owned; other values remain borrowed from their original source.
// No filesystem application, special-value normalization or deletion is implied.
type StreamFile struct {
	FinderInfo   [32]byte
	ResourceFork Value
	Attrs        []StreamAttr
}

// StreamLimits bounds work independently of retained memory. MaxFileBytes
// bounds input size or encoded output size, MaxValueBytes bounds each value,
// and MaxTotalValueBytes bounds the sum of all record and resource-fork lengths.
// Aliased spans count once per reference against that last limit. FinderInfo's
// fixed 32-byte slot does not count as a value. Zero permits zero bytes; it does
// not request an implicit default. Limits may be smaller than the wire limits.
type StreamLimits struct {
	MaxFileBytes       uint64
	MaxValueBytes      uint64
	MaxTotalValueBytes uint64
}

// DefaultStreamLimits allows the format's full representable sizes. It does not
// allocate those sizes: indexing retains at most the bounded header and records,
// and encoding copies through a fixed 64 KiB buffer. Applications should select
// lower work/disk budgets when accepting untrusted input.
func DefaultStreamLimits() StreamLimits {
	return StreamLimits{
		MaxFileBytes:       2 * uint64(math.MaxUint32),
		MaxValueBytes:      math.MaxUint32,
		MaxTotalValueBytes: 2 * uint64(math.MaxUint32),
	}
}

// ErrStreamBudget distinguishes a caller's resource limit from a malformed
// container or a format-width limit (ErrTooLarge).
var ErrStreamBudget = errors.New("appledouble: streaming budget exceeded")

func streamContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("appledouble: nil streaming context")
	}
	return ctx.Err()
}

func streamValueSize(value Value) (uint64, error) {
	if value == nil {
		return 0, nil
	}
	n := value.Size()
	if n < 0 {
		return 0, fmt.Errorf("appledouble: negative value size %d", n)
	}
	return uint64(n), nil
}

func (limits StreamLimits) addValue(size uint64, total *uint64) error {
	if size > limits.MaxValueBytes || *total > limits.MaxTotalValueBytes || size > limits.MaxTotalValueBytes-*total {
		return ErrStreamBudget
	}
	*total += size
	return nil
}

// streamRead permits EOF accompanying a complete read, as ReaderAt allows,
// but never treats a short read without an error as successful input.
func streamRead(ctx context.Context, source io.ReaderAt, buf []byte, off int64) error {
	if err := streamContext(ctx); err != nil {
		return err
	}
	n, err := source.ReadAt(buf, off)
	if n < 0 || n > len(buf) {
		return errors.New("appledouble: invalid ReaderAt count")
	}
	if n != len(buf) {
		if err == nil || errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func streamWrite(ctx context.Context, dst io.Writer, data []byte, written *int64) error {
	if err := streamContext(ctx); err != nil {
		return err
	}
	n, err := dst.Write(data)
	if n < 0 || n > len(data) {
		return errors.New("appledouble: invalid Writer count")
	}
	*written += int64(n)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
