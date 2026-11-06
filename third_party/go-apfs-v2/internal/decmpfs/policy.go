package decmpfs

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// EncodeOptions selects the content policy used by Apple's default filesystem
// compression queue. Host permissions and file eligibility remain the caller's
// responsibility; this operation only reads logical bytes and produces storage.
type EncodeOptions struct {
	// Type is 0 for the native default (LZVN), or a supported inline/fork type:
	// 3/4, 7/8, 9/10, 11/12 or 13/14. Unknown types are rejected.
	Type uint32
	// ResourceForkOnly disables the default inline-storage preference.
	ResourceForkOnly bool
}

// EncodedFile describes completed storage. A nil Attribute means the native
// content policy leaves the file uncompressed. Otherwise Attribute holds the
// complete com.apple.decmpfs value and ForkSize is the exact resource-fork
// extent (zero for inline storage). Attribute is owned by the caller.
type EncodedFile struct {
	Attribute []byte
	ForkSize  int64
}

var (
	errInlineSelected  = errors.New("inline compression selected")
	errSavingsDeclined = errors.New("native compression savings declined")
)

// Encode applies native size, savings and inline-storage decisions to logical
// bytes using bounded streaming encoding. It does not install attributes or
// change flags. The caller must stage destination privately and discard it on
// error, inline output or a declined result: later blocks can fail the savings
// threshold after earlier blocks have been written. Successful fork output
// must be truncated to ForkSize by its owner.
//
// Native default eligibility is 16 KiB < size <= 512 MiB. The savings threshold
// is page-rounded and accounts for fork framing; stored types bypass it. Inline
// output is limited to one block with at most 3,786 encoded payload bytes.
// These are compression decisions, not parser or caller working-memory limits.
func Encode(ctx context.Context, source io.ReaderAt, size int64, destination io.WriterAt, options EncodeOptions) (EncodedFile, error) {
	if err := ctx.Err(); err != nil {
		return EncodedFile{}, err
	}
	if source == nil || destination == nil || size < 0 {
		return EncodedFile{}, fmt.Errorf("invalid compression source or destination")
	}
	kind := options.Type
	if kind == 0 {
		kind = 8
	} else if kind&1 != 0 {
		kind++
	}
	if kind != 4 && kind != 8 && kind != 10 && kind != 12 && kind != 14 {
		return EncodedFile{}, fmt.Errorf("unsupported compression type %d", options.Type)
	}
	if size <= 16384 || size > 512<<20 {
		return EncodedFile{}, nil
	}
	limit := nativePayloadLimit(size, kind)
	var total int64
	var inline []byte
	accept := func(block []byte) error {
		total += int64(len(block))
		if total > limit {
			return errSavingsDeclined
		}
		if size <= BlockSize && !options.ResourceForkOnly && len(block) <= 3786 {
			header := encodedHeader(kind-1, size)
			inline = make([]byte, HeaderSize+len(block))
			copy(inline, header[:])
			copy(inline[HeaderSize:], block)
			return errInlineSelected
		}
		return nil
	}
	fork, err := encodeFork(ctx, source, size, kind, destination, accept)
	switch err {
	case errInlineSelected:
		return EncodedFile{Attribute: inline}, nil
	case errSavingsDeclined:
		return EncodedFile{}, nil
	case nil:
		return EncodedFile{Attribute: fork.Attribute[:], ForkSize: fork.Size}, nil
	default:
		return EncodedFile{}, err
	}
}

// The native budget is floor(ceil(size/4096)*80/100) pages, minus fork framing,
// with an inline-sized floor. Callers validate the native size window first.
func nativePayloadLimit(size int64, kind uint32) int64 {
	if kind == 10 {
		return 1<<32 - 1
	}
	blocks := (size + BlockSize - 1) / BlockSize
	overhead := 4 + 4*blocks
	if kind == 4 {
		overhead = 314 + 8*blocks
	}
	pages := (size + 4095) / 4096
	return max(pages*80/100*4096-overhead, 3786)
}
