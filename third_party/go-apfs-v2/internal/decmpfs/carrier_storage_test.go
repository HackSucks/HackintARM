package decmpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type carrierHeaderFault struct {
	n   int
	err error
}

func (carrierHeaderFault) Size() int64 { return 16 }
func (v carrierHeaderFault) ReadAt(p []byte, _ int64) (int, error) {
	copy(p, "fpmc")
	binary.LittleEndian.PutUint32(p[4:], 4)
	return v.n, v.err
}
func TestCarrierCompressionStorage(t *testing.T) {
	for _, method := range []uint32{1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14} {
		p := make([]byte, 16)
		copy(p, "fpmc")
		binary.LittleEndian.PutUint32(p[4:], method)
		got, err := UsesResourceFork(bytes.NewReader(p))
		if err != nil || got != (method%2 == 0) {
			t.Fatal(method, got, err)
		}
	}
	for _, value := range []appledouble.Value{nil, bytes.NewReader(nil), bytes.NewReader(make([]byte, 16)), carrierHeaderFault{n: 1, err: io.EOF}, carrierHeaderFault{n: 16, err: fs.ErrClosed}} {
		if _, err := UsesResourceFork(value); err == nil {
			t.Fatal("accepted malformed")
		}
	}
	p := make([]byte, 16)
	copy(p, "fpmc")
	binary.LittleEndian.PutUint32(p[4:], 5)
	if _, err := UsesResourceFork(bytes.NewReader(p)); err == nil {
		t.Fatal("accepted unknown method")
	}
	if got, err := UsesResourceFork(carrierHeaderFault{n: 16, err: io.EOF}); !got || err != nil {
		t.Fatal(got, err)
	}
	if _, err := UsesResourceFork(carrierHeaderFault{n: 1, err: fs.ErrClosed}); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
}
