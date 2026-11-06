package hostdata

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// ErrUnpackValueAllocation identifies an explicit allocation-budget refusal.
// It is not an emulated host ENOMEM: callers can inspect the joined diagnostic.
var ErrUnpackValueAllocation = errors.New("AppleDouble source allocation refused")

// UnpackSequentialOptions selects native read/effect order explicitly. Limits
// bound source size, individual values and total value bytes read (aliases count
// each time). MaxActiveBytes bounds simultaneously owned header, deferred ACL,
// and value/callback-copy bytes, excluding memory retained by the backend.
// Zero means a zero budget. No options change RestoreAppleDouble's safe snapshot
// contract. An operation may mutate the destination before a later source error.
type UnpackSequentialOptions struct {
	UnpackOptions
	Limits         appledouble.StreamLimits
	MaxActiveBytes uint64
}

// RestoreAppleDoubleSequential follows copyfile's source-read order: validate
// the base header, clean the destination, then read/execute each record before
// validating the next one. It preserves late failures and their partial effects.
// The fork is allocated before destination stat, and read after stat; fork
// failures can be masked by subsequent ACL/stat results while remaining in
// Failures. It never opens/closes endpoints or rolls back destination changes.
//
// Each value is allocated separately because UnpackBackend owns []byte writes.
// Large lossless transport should use indexed streaming values instead. The
// caller owns an immutable source and excludes concurrent destination mutation.
// Context cancellation is checked at acquisition/read boundaries; blocked IO is
// controlled by the caller. Native allocation failure is represented by explicit
// budgets rather than intentionally exhausting the Go process's memory.
func RestoreAppleDoubleSequential(ctx context.Context, source appledouble.Value, options UnpackSequentialOptions, backend UnpackBackend) (UnpackResult, error) {
	failed := UnpackResult{Code: -1, Copied: options.InitialCopied}
	if ctx == nil || source == nil || backend == nil {
		return failed, fs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return failed, err
	}
	size := source.Size()
	if size < 0 {
		return failed, fs.ErrInvalid
	}
	if uint64(size) > options.Limits.MaxFileBytes {
		return failed, appledouble.ErrStreamBudget
	}
	headerSize := min(uint64(size), uint64(appledouble.MaxHeader))
	if headerSize > options.MaxActiveBytes {
		return failed, errors.Join(ErrUnpackValueAllocation, appledouble.ErrStreamBudget)
	}
	s := &sequentialUnpack{ctx: ctx, source: source, options: options, header: make([]byte, int(headerSize))}
	if err := s.read(s.header, 0); err != nil {
		return failed, err
	}
	if len(s.header) < 82 || !appledouble.Sniff(s.header) || binary.BigEndian.Uint16(s.header[24:]) != 2 || binary.BigEndian.Uint32(s.header[26:]) != 9 {
		return failed, appledouble.ErrNotAppleDouble
	}
	s.finderOffset = binary.BigEndian.Uint32(s.header[30:])
	s.hasAttrs = binary.BigEndian.Uint32(s.header[34:]) > 32
	s.forkOffset = binary.BigEndian.Uint32(s.header[42:])
	if binary.BigEndian.Uint32(s.header[38:]) == 2 {
		s.forkSize = binary.BigEndian.Uint32(s.header[46:])
	}
	for _, off := range []int{0, 4, 26, 30, 34, 38, 42, 46} {
		s.swap32(off)
	}
	s.swap16(24)
	input := unpackInput{
		next: s.next, finder: s.finder, forkSize: uint64(s.forkSize), rawNames: true,
		allocateFork: func() ([]byte, error) { return s.allocate(uint64(s.forkSize)) },
		readFork:     func(b []byte) error { return s.read(b, int64(s.forkOffset)) },
	}
	return restoreAppleDouble(input, options.UnpackOptions, backend)
}

type sequentialUnpack struct {
	ctx                      context.Context
	source                   appledouble.Value
	options                  UnpackSequentialOptions
	header                   []byte
	finderOffset, forkOffset uint32
	forkSize                 uint32
	hasAttrs, initialized    bool
	remaining, entryOffset   int
	total, aclSize           uint64
}

func (s *sequentialUnpack) read(b []byte, off int64) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	// A native zero-length pread succeeds even beyond EOF. Some ReaderAt
	// implementations return EOF in that situation, so no source call is needed.
	if len(b) == 0 {
		return nil
	}
	n, err := s.source.ReadAt(b, off)
	if n < 0 || n > len(b) {
		return fmt.Errorf("invalid source read count: %w", fs.ErrInvalid)
	}
	if n != len(b) {
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

func (s *sequentialUnpack) allocate(size uint64) ([]byte, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	l := s.options.Limits
	base := uint64(len(s.header)) + s.aclSize
	if size > uint64(math.MaxInt) || size > l.MaxValueBytes || s.total > l.MaxTotalValueBytes || size > l.MaxTotalValueBytes-s.total || base > s.options.MaxActiveBytes || size > (s.options.MaxActiveBytes-base)/2 {
		return nil, errors.Join(ErrUnpackValueAllocation, appledouble.ErrStreamBudget)
	}
	s.total += size
	return make([]byte, int(size)), nil
}

func (s *sequentialUnpack) next() (appledouble.Attr, bool, error) {
	empty := appledouble.Attr{}
	if err := s.ctx.Err(); err != nil {
		return empty, false, err
	}
	if !s.initialized {
		s.initialized = true
		if s.hasAttrs {
			if len(s.header) < 120 || string(s.header[84:88]) != "ATTR" {
				return empty, false, fmt.Errorf("invalid ATTR header: %w", fs.ErrInvalid)
			}
			s.remaining = int(binary.BigEndian.Uint16(s.header[118:]))
			s.entryOffset = 120
			for _, off := range []int{84, 88, 92, 96, 100} {
				s.swap32(off)
			}
			s.swap16(116)
			s.swap16(118)
		}
	}
	if s.remaining == 0 {
		return empty, false, nil
	}
	off := s.entryOffset
	if off > len(s.header)-12 {
		return empty, false, fmt.Errorf("truncated ATTR entry: %w", fs.ErrInvalid)
	}
	valueOff := binary.BigEndian.Uint32(s.header[off:])
	length := binary.BigEndian.Uint32(s.header[off+4:])
	s.swap32(off)
	s.swap32(off + 4)
	s.swap16(off + 8)
	nameLength := int(s.header[off+10])
	if nameLength < 2 || nameLength > 128 || nameLength > len(s.header)-off-11 {
		return empty, false, fmt.Errorf("invalid ATTR name length: %w", fs.ErrInvalid)
	}
	name := s.header[off+11 : off+11+nameLength]
	if name[len(name)-1] != 0 {
		return empty, false, fmt.Errorf("unterminated ATTR name: %w", fs.ErrInvalid)
	}
	name = name[:bytes.IndexByte(name, 0)]
	value, err := s.allocate(uint64(length))
	if err != nil {
		return empty, false, err
	}
	if err := s.read(value, int64(valueOff)); err != nil {
		return empty, false, err
	}
	s.entryOffset += (11 + nameLength + 3) &^ 3
	s.remaining--
	if string(name) == appledouble.ACLTextName && length != 0 {
		s.aclSize = uint64(length)
	}
	return appledouble.Attr{Name: string(name), Value: value}, true, nil
}

func (s *sequentialUnpack) finder() ([32]byte, error) {
	var value [32]byte
	if err := s.ctx.Err(); err != nil {
		return value, err
	}
	if uint64(s.finderOffset)+32 > uint64(len(s.header)) {
		return value, fmt.Errorf("FinderInfo outside header: %w", fs.ErrInvalid)
	}
	copy(value[:], s.header[int(s.finderOffset):int(s.finderOffset)+32])
	return value, nil
}

func (s *sequentialUnpack) swap32(off int) {
	binary.LittleEndian.PutUint32(s.header[off:], binary.BigEndian.Uint32(s.header[off:]))
}

func (s *sequentialUnpack) swap16(off int) {
	binary.LittleEndian.PutUint16(s.header[off:], binary.BigEndian.Uint16(s.header[off:]))
}
