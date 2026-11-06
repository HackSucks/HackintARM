package hfsplus

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type forkFailureWriter struct {
	memWriterAt
	payload []byte
	err     error
	failed  bool
}

func (w *forkFailureWriter) WriteAt(p []byte, off int64) (int, error) {
	if bytes.Equal(p, w.payload) {
		w.failed = true
		return 0, w.err
	}
	return w.memWriterAt.WriteAt(p, off)
}

// Failed fork or attribute writes must never expose a successfully built image.
func TestWriterPreservesForkAndAttributeWriteFailures(t *testing.T) {
	for _, kind := range []string{"data", "resource", "attribute"} {
		for _, streamed := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/bytes", true: "/streamed"}[streamed], func(t *testing.T) {
				payload := bytes.Repeat([]byte{0xd7}, 8192)
				entry := &Entry{Name: "file", Mode: 0644}
				source := &countingOpen{content: payload}
				switch kind {
				case "data":
					if streamed {
						entry.Open, entry.Size = source.open, int64(len(payload))
					} else {
						entry.Data = payload
					}
				case "resource":
					if streamed {
						entry.ResourceForkValue = bytes.NewReader(payload)
					} else {
						entry.ResourceFork = payload
					}
				case "attribute":
					if streamed {
						entry.XattrValues = map[string]appledouble.Value{"com.example.failure": bytes.NewReader(payload)}
					} else {
						entry.Xattrs = map[string][]byte{"com.example.failure": payload}
					}
				}
				failure := errors.New("destination write failed")
				writer := &forkFailureWriter{payload: payload, err: failure}
				err := CreateImage(writer, 0, "IOFAIL", &Entry{Children: []*Entry{entry}}, nil)
				if !writer.failed || !errors.Is(err, failure) {
					t.Fatal("destination error lost", err)
				}
				want := map[string]string{"data": "writing file", "resource": "writing resource fork of file", "attribute": "writing attribute com.example.failure of file"}[kind]
				if !strings.Contains(err.Error(), want) {
					t.Fatal("wrong failure context", err)
				}
				if kind == "data" && streamed && (source.opens != 1 || source.closes != 1) {
					t.Fatal("failed streaming source not closed", source.opens, source.closes)
				}
			})
		}
	}
	failure := errors.New("source read failed")
	closed := false
	entry := &Entry{Name: "broken", Mode: 0644, Size: 8192, Open: func() (io.ReadCloser, error) { return &failureReadCloser{err: failure, closed: &closed}, nil }}
	err := CreateImage(&memWriterAt{}, 0, "SOURCEFAIL", &Entry{Children: []*Entry{entry}}, nil)
	if !closed || !errors.Is(err, failure) {
		t.Fatal("source failure or close lost", err)
	}
}

type failureReadCloser struct {
	err    error
	closed *bool
}

func (r *failureReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r *failureReadCloser) Close() error             { *r.closed = true; return nil }
