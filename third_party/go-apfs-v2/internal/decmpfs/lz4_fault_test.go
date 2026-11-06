package decmpfs

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lz4"
)

func TestLZ4RangeFailures(t *testing.T) {
	failure := errors.New("injected compression range error")
	for _, c := range []struct {
		name   string
		source io.ReaderAt
		size   int64
		want   error
	}{
		{"empty", bytes.NewReader(nil), 0, nil},
		{"short-first", bytes.NewReader(nil), 1, io.ErrUnexpectedEOF},
		{"first-error", encodeReaderFunc(func(p []byte, _ int64) (int, error) { p[0] = 0xff; return 1, failure }), 2, failure},
		{"stored-size", bytes.NewReader([]byte{0xff, 'a', 'b'}), 3, lz4.ErrOutputFull},
		{"short-body", bytes.NewReader([]byte{0xff}), 2, io.ErrUnexpectedEOF},
		{"body-error", encodeReaderFunc(func(p []byte, at int64) (int, error) {
			if at == 0 {
				p[0] = 0xff
				return 1, nil
			}
			p[0] = 'a'
			return 1, failure
		}), 2, failure},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, e := decompressLZ4Range(c.source, c.size, make([]byte, 1))
			if e == nil || c.want != nil && !errors.Is(e, c.want) {
				t.Fatal(e)
			}
		})
	}
	r := encodeReaderFunc(func(p []byte, at int64) (int, error) {
		n, _ := bytes.NewReader([]byte{0xff, 'a'}).ReadAt(p, at)
		return n, io.EOF
	})
	out := make([]byte, 1)
	if n, e := decompressLZ4Range(r, 2, out); n != 1 || e != nil || out[0] != 'a' {
		t.Fatal(n, e)
	}
}
