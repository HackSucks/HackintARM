package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestFilesystemMetadataNativeProviderFailures(t *testing.T) {
	v, root, _ := newMetadataTestView(t, false)
	ctx := context.Background()
	v.ops.list = func(*os.File, int) ([]string, error) { return []string{"attribute"}, nil }
	if names, err := v.List(ctx, 100); err != nil || len(names) != 1 {
		t.Fatal(names, err)
	}
	v.ops.read = func(*os.File, string, int) ([]byte, bool, error) { return []byte("value"), true, nil }
	if b, p, err := v.Read(ctx, "attribute", 10); err != nil || !p || string(b) != "value" {
		t.Fatal(string(b), p, err)
	}
	v.ops.size = func(*os.File, string) (int, bool, error) { return 0, false, io.ErrUnexpectedEOF }
	if _, _, err := v.OpenValue(ctx, ResourceForkName); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	v.ops.size = func(*os.File, string) (int, bool, error) { return 0, false, nil }
	if _, p, err := v.OpenValue(ctx, ResourceForkName); p || err != nil {
		t.Fatal(p, err)
	}
	v.ops.size = func(*os.File, string) (int, bool, error) { return 5, true, nil }
	v.ops.fork = func(*os.File, bool) (*os.File, error) { return nil, os.ErrPermission }
	if _, _, err := v.OpenValue(ctx, ResourceForkName); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	for _, fallback := range []error{errors.ErrUnsupported, os.ErrNotExist} {
		v.ops.fork = func(*os.File, bool) (*os.File, error) { return nil, fallback }
		if b, p, err := v.Read(ctx, ResourceForkName, 10); err != nil || !p || string(b) != "value" {
			t.Fatal(string(b), p, err)
		}
	}
	v.ops.fork = func(*os.File, bool) (*os.File, error) { return root.Open("input") }
	value, p, err := v.OpenValue(ctx, ResourceForkName)
	if err != nil || !p {
		t.Fatal(p, err)
	}
	if err = value.closer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = value.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if err = value.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	v.ops.fork = func(*os.File, bool) (*os.File, error) {
		f, e := root.Open("input")
		if e == nil {
			e = f.Close()
		}
		return f, e
	}
	if _, _, err = v.OpenValue(ctx, ResourceForkName); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestFilesystemMetadataSidecarFailures(t *testing.T) {
	v, root, _ := newMetadataTestView(t, true)
	ctx := context.Background()
	seed, err := readMetadataViewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("._input", seed, 0600); err != nil {
		t.Fatal(err)
	}
	original := v.ops.sidecar
	v.ops.sidecar = func(*os.Root, string) (*os.File, error) { return nil, os.ErrPermission }
	if _, err = v.List(ctx, 100); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if _, _, err = v.OpenValue(ctx, "attribute"); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	v.ops.sidecar = func(r *os.Root, n string) (*os.File, error) {
		f, e := original(r, n)
		if e == nil {
			e = f.Close()
		}
		return f, e
	}
	if _, err = v.List(ctx, 100); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	v.ops.sidecar = func(r *os.Root, n string) (*os.File, error) { return r.Open("input") }
	if _, err = v.List(ctx, 100); !errors.Is(err, ErrMetadataIdentity) {
		t.Fatal(err)
	}
	v.ops.sidecar = original
	// Bad ATTR framing is an error, not fabricated absence. Magic/truncation
	// controls already come from every native producer's corpus.
	bad := bytes.Clone(seed)
	bad[84] = 'X'
	if err = root.WriteFile("._input", bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = v.List(ctx, 100); err == nil {
		t.Fatal("invalid ATTR header accepted")
	}
	// Nonempty values isolate duplicate-name validation from the earlier
	// native rejection of COPYFILE_PACK zero-offset empty values.
	duplicate := &appledouble.StreamFile{Attrs: []appledouble.StreamAttr{{Name: "duplicate", Value: bytes.NewReader([]byte("one"))}, {Name: "duplicate", Value: bytes.NewReader([]byte("two"))}}}
	var buf bytes.Buffer
	if _, err = duplicate.EncodeTo(ctx, &buf, appledouble.DefaultStreamLimits()); err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("._input", buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = v.List(ctx, 100); !errors.Is(err, ErrXattrListMalformed) {
		t.Fatal(err)
	}
	if err = root.Remove("input"); err != nil {
		t.Fatal(err)
	}
	if _, err = v.List(ctx, 100); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err = v.parent.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = v.List(ctx, 100); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

type metadataBrokenValue struct {
	n   int
	err error
}

func (metadataBrokenValue) Size() int64                             { return 286 }
func (v metadataBrokenValue) ReadAt(p []byte, _ int64) (int, error) { return min(v.n, len(p)), v.err }

func TestFilesystemMetadataBlankForkBoundaries(t *testing.T) {
	ctx := context.Background()
	blank := make([]byte, 286)
	copy(blank[16:], "This resource fork intentionally left blank   \x00")
	for _, tc := range []struct {
		value   appledouble.Value
		visible bool
		err     error
	}{
		{nil, false, nil}, {bytes.NewReader(nil), false, nil}, {bytes.NewReader(blank), false, nil},
		{bytes.NewReader(append(bytes.Clone(blank), 0)), true, nil},
		{metadataBrokenValue{0, io.ErrClosedPipe}, false, io.ErrClosedPipe},
		{metadataBrokenValue{1, nil}, false, io.ErrUnexpectedEOF},
		{metadataBrokenValue{100, io.EOF}, true, nil},
	} {
		got, err := filesystemResourceForkVisible(ctx, tc.value)
		if got != tc.visible || !errors.Is(err, tc.err) {
			t.Fatal(got, err, tc)
		}
	}
	blank[16] = 'X'
	if visible, err := filesystemResourceForkVisible(ctx, bytes.NewReader(blank)); !visible || err != nil {
		t.Fatal(visible, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := filesystemResourceForkVisible(canceled, bytes.NewReader(blank)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestFilesystemMetadataAcquisitionBoundaries(t *testing.T) {
	_, root, _ := newMetadataTestView(t, true)
	ctx := context.Background()
	for _, name := range []string{"absent/input", "input/leaf"} {
		if got, err := OpenFilesystemMetadata(ctx, root, name); err == nil {
			got.Close()
			t.Fatal("invalid parent accepted")
		}
	}
	if _, err := OpenFilesystemMetadata(ctx, nil, "input"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	if got, err := openFilesystemMetadata(canceled, root, "input", func(*os.File) (bool, error) { cancel(); return true, nil }); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(got, err)
	}
	// A capability root does not grant access to its parent's sidecar. Never
	// reinterpret a planted ._. inside a subdirectory as that directory's data.
	for _, name := range []string{".", "./", "input/..", "input/"} {
		v, err := openFilesystemMetadata(ctx, root, name, func(*os.File) (bool, error) { return true, nil })
		if v != nil || !errors.Is(err, os.ErrInvalid) {
			t.Fatal("ambiguous final component accepted", name, v, err)
		}
	}
	if err := root.WriteFile("._input", nil, 0600); err != nil {
		t.Fatal(err)
	}
	v, err := openFilesystemMetadata(ctx, root, "._input", func(*os.File) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err = v.List(ctx, 100); !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
}
