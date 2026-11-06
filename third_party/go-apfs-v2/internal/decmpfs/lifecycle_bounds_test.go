package decmpfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestDecoderInvalidLifecycle(t *testing.T) {
	var absent *Handle
	if absent.Close() == nil || absent.loadCompressedBlockOffsets() == nil {
		t.Fatal("nil handle accepted")
	}
	if _, err := absent.ReadSegmentData(0, []byte{0}); err == nil {
		t.Fatal("nil read accepted")
	}
	if _, err := absent.SeekSegmentOffset(0, 0); err == nil {
		t.Fatal("nil seek accepted")
	}
	if _, err := NewHandle(nil, 0, MethodNone); err == nil {
		t.Fatal("nil source accepted")
	}
	h, _, _, _ := largeIndexFixture(t, true)
	for _, args := range []struct {
		segment int
		data    []byte
	}{{1, []byte{0}}, {0, nil}} {
		if _, err := h.ReadSegmentData(args.segment, args.data); err == nil {
			t.Fatal("invalid read accepted")
		}
	}
	for _, args := range []struct {
		segment int
		at      int64
	}{{1, 0}, {0, -1}} {
		if _, err := h.SeekSegmentOffset(args.segment, args.at); err == nil {
			t.Fatal("invalid seek accepted")
		}
	}
}

func TestDecoderPropagatesHeaderAndBlockFailures(t *testing.T) {
	fault := errors.New("source failure")
	for _, short := range []bool{false, true} {
		for _, at := range []int64{0, 4} {
			h, s, _, _ := largeIndexFixture(t, true)
			s.failAt = at
			s.short = short
			s.err = fault
			if _, err := h.ReadSegmentData(0, make([]byte, 1)); err == nil || (!short && !errors.Is(err, fault)) {
				t.Fatalf("header failure short=%t at=%d: %v", short, at, err)
			}
		}
	}
	for _, short := range []bool{false, true} {
		h, s, _, count := largeIndexFixture(t, true)
		if err := h.loadCompressedBlockOffsets(); err != nil {
			t.Fatal(err)
		}
		s.failAt = int64(h.largeIndex.end)
		s.short = short
		s.err = fault
		if _, err := h.SeekSegmentOffset(0, int64(count-1)*BlockSize); err != nil {
			t.Fatal(err)
		}
		if _, err := h.ReadSegmentData(0, []byte{0}); err == nil || (!short && !errors.Is(err, fault)) {
			t.Fatalf("block failure: %v", err)
		}
	}
	h, s, _, _ := largeIndexFixture(t, true)
	if err := h.loadCompressedBlockOffsets(); err != nil {
		t.Fatal(err)
	}
	s.failAt = 264
	s.err = fault
	if _, err := h.ReadSegmentData(0, []byte{0}); !errors.Is(err, fault) {
		t.Fatalf("index failure: %v", err)
	}
}

func TestDecoderLogicalEndAndPartialFailure(t *testing.T) {
	const blocks = 16384
	// The first full block is a stored LZVN block; later entries are small.
	// An injected second-block read failure must preserve the consumed offset.
	end := (blocks + 1) * 4
	s := &indexSource{data: make([]byte, end+BlockSize+1+(blocks-1)*2), failAt: -1}
	for i := 0; i <= blocks; i++ {
		position := end
		if i > 0 {
			position += BlockSize + 1 + (i-1)*2
		}
		binary.LittleEndian.PutUint32(s.data[i*4:], uint32(position))
	}
	s.data[end] = 6
	copy(s.data[end+1:], bytes.Repeat([]byte{'X'}, BlockSize))
	for i := end + BlockSize + 1; i < len(s.data); i += 2 {
		copy(s.data[i:], []byte{6, 'A'})
	}
	h, err := NewHandle(s, (blocks-1)*BlockSize+1, MethodLZVN)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	fault := errors.New("second block")
	s.failAt = int64(end + BlockSize + 1)
	s.err = fault
	buffer := make([]byte, BlockSize+1)
	n, err := h.ReadSegmentData(0, buffer)
	if n != BlockSize || !errors.Is(err, fault) || h.CurrentSegmentOffset != BlockSize {
		t.Fatalf("partial read n=%d offset=%d err=%v", n, h.CurrentSegmentOffset, err)
	}
	if !bytes.Equal(buffer[:n], bytes.Repeat([]byte{'X'}, BlockSize)) {
		t.Fatal("partial data changed")
	}
	s.failAt = -1
	_, err = h.SeekSegmentOffset(0, int64(h.UncompressedDataSize)-1)
	if err != nil {
		t.Fatal(err)
	}
	buffer = bytes.Repeat([]byte{0xa5}, 10)
	n, err = h.ReadSegmentData(0, buffer)
	if n != 1 || err != nil || buffer[0] != 'A' || !bytes.Equal(buffer[1:], bytes.Repeat([]byte{0xa5}, 9)) {
		t.Fatalf("logical tail n=%d data=%x err=%v", n, buffer, err)
	}
	if _, err = h.ReadSegmentData(0, buffer); err != io.EOF {
		t.Fatalf("end: %v", err)
	}
}

func TestDecoderLeafFailures(t *testing.T) {
	for _, args := range []struct {
		source, target []byte
		size           *int
		method         int
	}{{nil, []byte{0}, new(int), MethodNone}, {[]byte{0}, nil, new(int), MethodNone}, {[]byte{0}, []byte{0}, nil, MethodNone}, {[]byte{0}, []byte{0}, new(int), 99}} {
		if err := Decompress(args.source, args.method, args.target, args.size); err == nil {
			t.Fatal("invalid leaf arguments accepted")
		}
	}
	for _, method := range []int{MethodDeflate, MethodLZVN, MethodLZFSE} {
		marker := byte(255)
		if method == MethodLZVN {
			marker = 6
		}
		size := 0
		if err := Decompress([]byte{marker, 'A'}, method, []byte{0}, &size); err == nil {
			t.Fatal("stored block exceeds capacity")
		}
		size = 1
		if err := Decompress([]byte{0, 1, 2}, method, []byte{0}, &size); err == nil {
			t.Fatal("malformed compressed stream accepted")
		}
	}
	var compressed bytes.Buffer
	z := zlib.NewWriter(&compressed)
	if _, err := z.Write([]byte("bad checksum control")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	b := compressed.Bytes()
	b[len(b)-1] ^= 1
	out := make([]byte, 128)
	size := len(out)
	if err := Decompress(b, MethodDeflate, out, &size); err == nil {
		t.Fatal("corrupt zlib checksum accepted")
	}
}
