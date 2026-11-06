package apfs

import (
	"bytes"
	"io"
	"testing"
)

// TestExtendedAttributeReadTerminates is the regression test for an infinite
// loop. ExtendedAttribute.Read used to pass io.EOF through from the underlying
// stream and nothing else, so a stream that signalled its end by returning
// (0, nil) rather than io.EOF turned any io.Reader loop over the attribute —
// io.ReadAll in Volume.Xattrs, for instance — into an endless one.
//
// The reader now bounds itself by the attribute's own size, so it terminates
// whatever the stream underneath chooses to report.
func TestExtendedAttributeReadTerminates(t *testing.T) {
	value := []byte("attribute value that spans more than one read")

	stream, err := NewDataStreamFromData(value)
	if err != nil {
		t.Fatalf("NewDataStreamFromData: %v", err)
	}
	// Replace the reader with one that never reports io.EOF, which is the
	// behaviour that used to hang.
	stream.readerAt = neverEOFReaderAt{data: value}

	attr := &ExtendedAttribute{DataStream: stream}

	got, err := io.ReadAll(readerFromXattr{attr})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("read %q, want %q", got, value)
	}
}

// TestExtendedAttributeReadStopsAtSize checks a read is bounded by the value's
// length rather than by whatever the stream is willing to hand back, so an
// attribute never reports more data than it has.
func TestExtendedAttributeReadStopsAtSize(t *testing.T) {
	value := []byte("short")

	stream, err := NewDataStreamFromData(value)
	if err != nil {
		t.Fatalf("NewDataStreamFromData: %v", err)
	}
	stream.readerAt = neverEOFReaderAt{data: value}
	attr := &ExtendedAttribute{DataStream: stream}

	buf := make([]byte, 64)
	n, err := attr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if n != len(value) {
		t.Errorf("read %d bytes, want %d", n, len(value))
	}

	// A second read is past the end and must say so rather than repeating.
	if _, err := attr.Read(buf); err != io.EOF {
		t.Errorf("reading past the end returned %v, want io.EOF", err)
	}
}

// neverEOFReaderAt serves data and reports success even past the end, which is
// how a stream can starve an io.Reader loop that trusts it to say when to stop.
type neverEOFReaderAt struct{ data []byte }

func (r neverEOFReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, nil // deliberately not io.EOF
	}
	return copy(p, r.data[off:]), nil
}
