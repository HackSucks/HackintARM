package hostdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"
	"unicode/utf16"
)

func backupRecord(id, attributes uint32, name string, data []byte) []byte {
	units := utf16.Encode([]rune(name))
	p := make([]byte, 20+2*len(units)+len(data))
	binary.LittleEndian.PutUint32(p, id)
	binary.LittleEndian.PutUint32(p[4:], attributes)
	binary.LittleEndian.PutUint64(p[8:], uint64(len(data)))
	binary.LittleEndian.PutUint32(p[16:], uint32(2*len(units)))
	for i, v := range units {
		binary.LittleEndian.PutUint16(p[20+2*i:], v)
	}
	copy(p[20+2*len(units):], data)
	return p
}
func backupExtent(offset uint64, data string) []byte {
	p := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint64(p, offset)
	copy(p[8:], data)
	return backupRecord(9, 8, "", p)
}
func TestReplacementBackupSparseStreams(t *testing.T) {
	main := bytes.Join([][]byte{backupRecord(1, 8, "", nil), backupExtent(4<<30, "old main"), backupExtent(5<<30, "")}, nil)
	metadata := bytes.Join([][]byte{backupRecord(2, 0, "", []byte("EA")), backupRecord(4, 0, ":normal:$DATA", []byte("normal")), backupRecord(4, 8, ":sparse:$DATA", nil), backupExtent(65536, "named data"), backupExtent(131072, "")}, nil)
	input := bytes.Join([][]byte{main, metadata, backupRecord(5, 0, "", []byte("link")), backupRecord(7, 0, "", []byte("identity")), backupRecord(1, 0, "", []byte("dense main"))}, nil)
	var output bytes.Buffer
	if err := filterReplacementStreams(bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), metadata) {
		t.Fatalf("copied main data or lost metadata: %x", output.Bytes())
	}
}
func TestReplacementBackupMalformed(t *testing.T) {
	sparse := backupRecord(1, 8, "", nil)
	cases := map[string][]byte{
		"unknown":         backupRecord(8, 0, "", nil),
		"orphan":          backupExtent(0, "x"),
		"short-extent":    append(append([]byte{}, sparse...), backupRecord(9, 8, "", nil)...),
		"overflow-offset": append(append([]byte{}, sparse...), backupExtent(math.MaxUint64, "")...),
		"overflow-length": append(append([]byte{}, sparse...), backupExtent(math.MaxInt64, "x")...),
		"main-name":       backupRecord(1, 0, "x", nil),
		"empty-name":      backupRecord(4, 0, "", nil),
		"slash-name":      backupRecord(4, 0, ":a/b:$DATA", nil),
		"null-name":       backupRecord(4, 0, ":a\x00b:$DATA", nil),
		"long-name":       backupRecord(4, 0, string(make([]byte, 32769)), nil),
	}
	for _, field := range []string{"odd-name", "size-overflow"} {
		p := backupRecord(4, 0, ":x:$DATA", nil)
		if field == "odd-name" {
			binary.LittleEndian.PutUint32(p[16:], 1)
		} else {
			binary.LittleEndian.PutUint64(p[8:], math.MaxUint64)
		}
		cases[field] = p
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if err := filterReplacementStreams(bytes.NewReader(input), io.Discard); err == nil {
				t.Fatal("accepted malformed stream")
			}
		})
	}
	valid := append(backupRecord(4, 8, ":sparse:$DATA", nil), backupExtent(0, "data")...)
	// Every partial header, name, offset and payload must fail. A complete first
	// record is a valid empty sparse stream and is tested separately.
	boundary := len(backupRecord(4, 8, ":sparse:$DATA", nil))
	for n := 1; n < len(valid); n++ {
		if n == boundary {
			continue
		}
		if err := filterReplacementStreams(bytes.NewReader(valid[:n]), io.Discard); err == nil {
			t.Fatalf("accepted truncated stream at %d", n)
		}
	}
}

type backupFailWriter struct{ remaining int }

func (w *backupFailWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, io.ErrClosedPipe
	}
	w.remaining -= len(p)
	return len(p), nil
}
func TestReplacementBackupWriteFailures(t *testing.T) {
	// Align each header/name/offset write across the bounded writer's flush
	// boundary, then inject errors in both flushes and direct payload writes.
	for _, padding := range []int{0, 65480, 65490, 65491, 65500, 65516, 65520, 65536} {
		name := ":" + string(bytes.Repeat([]byte{'a'}, 32760)) + ":$DATA"
		input := bytes.Join([][]byte{backupRecord(2, 0, "", make([]byte, padding)), backupRecord(4, 8, ":x:$DATA", nil), backupExtent(0, "payload"), backupRecord(4, 0, name, make([]byte, 65536))}, nil)
		for _, limit := range []int{0, 65536, 131072, len(input) - 1} {
			if limit >= len(input) {
				continue
			}
			w := &backupFailWriter{limit}
			if err := filterReplacementStreams(bytes.NewReader(input), w); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("padding=%d limit=%d: %v", padding, limit, err)
			}
		}
	}
}
