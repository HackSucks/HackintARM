package largefork

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type cancelHeader struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelHeader) Write(p []byte) (int, error) {
	n, e := w.Buffer.Write(p)
	w.cancel()
	return n, e
}

type wireValue struct {
	header []byte
	fork   *io.SectionReader
}

func (v wireValue) Size() int64 { return int64(len(v.header)) + v.fork.Size() }
func (v wireValue) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	if off < int64(len(v.header)) {
		n = copy(p, v.header[off:])
		p = p[n:]
		off += int64(n)
	}
	if len(p) == 0 {
		return n, nil
	}
	m, e := v.fork.ReadAt(p, off-int64(len(v.header)))
	return n + m, e
}
func TestCarrierLargeAppleDoubleWireBoundary(t *testing.T) {
	source := &Value{}
	fork := io.NewSectionReader(source, 0, math.MaxUint32)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	header := &cancelHeader{cancel: cancel}
	n, err := (&appledouble.StreamFile{ResourceFork: fork}).EncodeTo(ctx, header, appledouble.DefaultStreamLimits())
	if !errors.Is(err, context.Canceled) || n != int64(header.Len()) || header.Len() == 0 || source.Reads != 0 {
		t.Fatal(n, header.Len(), source.Reads, err)
	}
	// The composite represents every byte of a legitimate wire file, including
	// positions beyond uint32 after its header. Only bounded spans are read.
	wire := wireValue{header: header.Bytes(), fork: fork}
	decoded, err := appledouble.DecodeStream(context.Background(), wire, appledouble.DefaultStreamLimits())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ResourceFork.Size() != math.MaxUint32 || wire.Size() <= math.MaxUint32 {
		t.Fatal(decoded.ResourceFork.Size(), wire.Size())
	}
	got, want := make([]byte, 16), make([]byte, 16)
	off := int64(math.MaxUint32) - 16
	if _, err = decoded.ResourceFork.ReadAt(got, off); err != nil {
		t.Fatal(err)
	}
	if _, err = source.ReadAt(want, off); err != nil || !bytes.Equal(got, want) {
		t.Fatal(got, want, err)
	}
	var output bytes.Buffer
	before := source.Reads
	if n, err := (&appledouble.StreamFile{ResourceFork: source}).EncodeTo(context.Background(), &output, appledouble.DefaultStreamLimits()); n != 0 || !errors.Is(err, appledouble.ErrTooLarge) || output.Len() != 0 || source.Reads != before {
		t.Fatal(n, output.Len(), source.Reads, err)
	}
}
