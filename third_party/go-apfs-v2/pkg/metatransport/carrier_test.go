package metatransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

var testContext = context.Background()

func digest(b []byte) BlobRef {
	h := sha256.Sum256(b)
	return BlobRef{hex.EncodeToString(h[:]), int64(len(b))}
}
func fixture(t *testing.T) (*Store, string, string) {
	t.Helper()
	base := t.TempDir()
	p, m := filepath.Join(base, "payload"), filepath.Join(base, "metadata")
	for _, n := range []string{p, m} {
		if e := os.Mkdir(n, 0700); e != nil {
			t.Fatal(e)
		}
	}
	s, e := Open(p, m, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, p, m
}
func mustBlob(t *testing.T, s *Store, b []byte) BlobRef {
	t.Helper()
	r, e := s.PutBlob(testContext, bytes.NewReader(b), int64(len(b)))
	if e != nil {
		t.Fatal(e)
	}
	if r != digest(b) {
		t.Fatal(r)
	}
	return r
}
func fileRecord(t *testing.T, p string) Record {
	t.Helper()
	b := []byte("payload")
	if e := os.WriteFile(filepath.Join(p, "file"), b, 0600); e != nil {
		t.Fatal(e)
	}
	r := digest(b)
	return Record{Original: "original:name", Materialized: "file", Kind: "file", MaterializedKind: "file", Payload: &r}
}
func TestCarrierRoundTrip(t *testing.T) {
	s, p, m := fixture(t)
	r := fileRecord(t, p)
	ref := mustBlob(t, s, bytes.Repeat([]byte{3}, 150000))
	empty := mustBlob(t, s, nil)
	mustBlob(t, s, nil)
	r.Attributes = []Attribute{{"Case", ref}, {"case", empty}, {"user.empty", empty}}
	r.AppleDouble = &ref
	r.Darwin.Security = &ref
	r.Darwin.Identity = &ref
	r.Darwin.QuarantineContext = &ref
	zero := uint32(0)
	r.Darwin.Mode = &zero
	r.Darwin.UID = &zero
	want := Manifest{Version: 1, Records: []Record{r, {Original: ".", Materialized: ".", Kind: "directory", MaterializedKind: "directory"}}}
	if e := s.Commit(testContext, want, 0); e != nil {
		t.Fatal(e)
	}
	got, e := s.Load(testContext)
	if e != nil {
		t.Fatal(e)
	}
	if got.Generation != 1 || got.Records[0].Darwin.Mode == nil || *got.Records[0].Darwin.Mode != 0 {
		t.Fatal(got)
	}
	f, e := s.OpenBlob(testContext, ref)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	f.Close()
	if e != nil || digest(b) != ref {
		t.Fatal(e)
	}
	if e = s.VerifyPayload(testContext, r); e != nil {
		t.Fatal(e)
	}
	if e = s.VerifyPayload(testContext, want.Records[1]); e != nil {
		t.Fatal(e)
	}
	if e = s.Commit(testContext, want, 0); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e = s.Commit(testContext, got, 1); e != nil {
		t.Fatal(e)
	}
	// Owned bytes do not change after a caller mutates a prior Load result.
	got.Records[0].Attributes[0].Name = "changed"
	again, e := s.Load(testContext)
	if e != nil || again.Records[0].Attributes[0].Name != "Case" {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(p, "file"), []byte("edited"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = s.VerifyPayload(testContext, r); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if _, e = s.Load(testContext); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(m, ".lock"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e = s.Commit(testContext, again, 2); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestCarrierInputValidation(t *testing.T) {
	s, p, _ := fixture(t)
	base := fileRecord(t, p)
	mutations := []func(*Manifest){
		func(m *Manifest) { m.Version = 2 }, func(m *Manifest) { m.Records[0].Original = "../escape" }, func(m *Manifest) { m.Records[0].Original = "bad\x00" },
		func(m *Manifest) { m.Records[0].Materialized = "../escape" },
		func(m *Manifest) { m.Records = append(m.Records, m.Records[0]) }, func(m *Manifest) { n := m.Records[0]; n.Original = "other"; m.Records = append(m.Records, n) },
		func(m *Manifest) { m.Records[0].Kind = "socket" }, func(m *Manifest) { m.Records[0].MaterializedKind = "socket" }, func(m *Manifest) { m.Records[0].MaterializedKind = "directory" },
		func(m *Manifest) { m.Records[0].Target = "bad" }, func(m *Manifest) { m.Records[0].Payload = nil }, func(m *Manifest) { r := BlobRef{SHA256: "x"}; m.Records[0].Payload = &r },
		func(m *Manifest) { m.Records[0].Original = "." }, func(m *Manifest) { m.Records[0].Attributes = []Attribute{{Name: ""}} }, func(m *Manifest) { m.Records[0].Attributes = []Attribute{{Name: "x\x00"}} },
		func(m *Manifest) {
			m.Records[0].Attributes = []Attribute{{Name: "x", Value: digest(nil)}, {Name: "x", Value: digest(nil)}}
		}, func(m *Manifest) { m.Records[0].AppleDouble = &BlobRef{} },
	}
	if runtime.GOOS == "windows" {
		mutations = append(mutations, func(m *Manifest) { m.Records[0].Materialized = "c:foo" })
	}
	for i, change := range mutations {
		m := Manifest{Version: 1, Records: []Record{base}}
		change(&m)
		if e := s.Commit(testContext, m, 0); !errors.Is(e, ErrInvalid) {
			t.Fatalf("%d: %v", i, e)
		}
	}
	s.limits.Records = 0
	if e := s.validate(Manifest{Version: 1, Records: []Record{base}}); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	s.limits = DefaultLimits()
	s.limits.Attributes = 0
	base.Attributes = []Attribute{{"x", digest(nil)}}
	if e := s.validate(Manifest{Version: 1, Records: []Record{base}}); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	s.limits = DefaultLimits()
	s.limits.BlobBytes = 0
	base.Attributes[0].Value = digest([]byte{1})
	if e := s.validate(Manifest{Version: 1, Records: []Record{base}}); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
}
func TestCarrierOpenAndClosed(t *testing.T) {
	s, p, m := fixture(t)
	for _, pair := range [][2]string{{p, p}, {p, filepath.Dir(p)}, {filepath.Dir(p), m}, {p, filepath.Join(m, "missing")}} {
		if opened, e := Open(pair[0], pair[1], DefaultLimits()); e == nil {
			opened.Close()
			t.Fatal(pair)
		}
	}
	for _, l := range []Limits{{ManifestBytes: -1}, {BlobBytes: -1}, {Records: -1}, {Attributes: -1}, {ManifestBytes: int64(^uint64(0) >> 1)}} {
		if _, e := Open(p, m, l); !errors.Is(e, ErrLimit) {
			t.Fatal(e)
		}
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Load(testContext); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if _, e := s.PutBlob(testContext, bytes.NewReader(nil), 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if _, e := s.OpenBlob(testContext, digest(nil)); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if e := s.Commit(testContext, Manifest{}, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if e := s.VerifyPayload(testContext, Record{}); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
}
func TestCarrierCorruption(t *testing.T) {
	s, p, m := fixture(t)
	r := fileRecord(t, p)
	ref := mustBlob(t, s, []byte("value"))
	r.Attributes = []Attribute{{"x", ref}}
	manifest := Manifest{Version: 1, Records: []Record{r}}
	if e := s.Commit(testContext, manifest, 0); e != nil {
		t.Fatal(e)
	}
	for _, b := range [][]byte{[]byte("shorter"), []byte("other")} {
		if e := os.WriteFile(filepath.Join(m, blobName(ref)), b, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := s.Load(testContext); !errors.Is(e, ErrCorrupt) {
			t.Fatal(e)
		}
		if _, e := s.PutBlob(testContext, strings.NewReader("value"), 5); !errors.Is(e, ErrCorrupt) {
			t.Fatal(e)
		}
	}
	if e := os.Remove(filepath.Join(m, blobName(ref))); e != nil {
		t.Fatal(e)
	}
	if e := s.Commit(testContext, manifest, 0); !errors.Is(e, ErrCorrupt) {
		t.Fatal(e)
	}
	if _, e := s.OpenBlob(testContext, BlobRef{}); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	s.limits.BlobBytes = 0
	if _, e := s.OpenBlob(testContext, ref); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
}
func TestCarrierMalformedManifest(t *testing.T) {
	s, _, m := fixture(t)
	for _, b := range []string{"", `null`, `{}`, `{"version":1,"generation":1,"records":[],"unknown":0}`, `{"version":1,"version":1}`, `{"version":1,"generation":0,"records":[]}`, `{} {}`, `{"a":`, strings.Repeat("[", 34) + strings.Repeat("]", 34), `{"version":1,"generation":1,"records":[{"original":"x","original":"y"}]}`} {
		if e := os.WriteFile(filepath.Join(m, "manifest.json"), []byte(b), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := s.Load(testContext); e == nil {
			t.Fatal(b)
		}
	}
	s.limits.ManifestBytes = 1
	if _, e := s.Load(testContext); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
}

type badReader struct {
	n   int
	err error
}

func (r badReader) ReadAt(b []byte, _ int64) (int, error) { n := min(len(b), r.n); return n, r.err }

type badWriter struct {
	n   int
	err error
}

func (w badWriter) Write(b []byte) (int, error) { return min(len(b), w.n), w.err }
func TestCarrierBoundedIO(t *testing.T) {
	sentinel := errors.New("injected")
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	for _, tc := range []struct {
		ctx  context.Context
		src  io.ReaderAt
		dst  io.Writer
		size int64
		want error
	}{
		{testContext, nil, io.Discard, 0, ErrInvalid}, {testContext, bytes.NewReader(nil), io.Discard, -1, ErrInvalid}, {cancelled, bytes.NewReader([]byte{1}), io.Discard, 1, context.Canceled},
		{testContext, badReader{0, io.EOF}, io.Discard, 1, io.ErrUnexpectedEOF}, {testContext, badReader{1, sentinel}, io.Discard, 1, sentinel},
		{testContext, bytes.NewReader([]byte{1}), badWriter{0, nil}, 1, io.ErrShortWrite}, {testContext, bytes.NewReader([]byte{1}), badWriter{0, sentinel}, 1, sentinel},
	} {
		if e := copyExact(tc.ctx, tc.dst, tc.src, tc.size); !errors.Is(e, tc.want) {
			t.Fatal(e)
		}
	}
	if e := copyExact(testContext, io.Discard, badReader{1, io.EOF}, 1); e != nil {
		t.Fatal(e)
	}
	s, _, m := fixture(t)
	if _, e := s.PutBlob(testContext, bytes.NewReader(nil), 1); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(m)
	if e != nil || len(entries) != 0 {
		t.Fatal(entries, e)
	}
	for _, size := range []int64{-1, DefaultLimits().BlobBytes + 1} {
		if _, e := s.PutBlob(testContext, bytes.NewReader(nil), size); !errors.Is(e, ErrLimit) {
			t.Fatal(e)
		}
	}
	if _, e := s.Load(cancelled); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestCarrierDirectoriesAndFiles(t *testing.T) {
	s, p, m := fixture(t)
	if _, e := s.Load(testContext); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	if e := s.Commit(testContext, Manifest{Version: 1, Generation: 1}, 1); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e := s.Commit(testContext, Manifest{Version: 1}, 1); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e := s.Commit(testContext, Manifest{Version: 1, Generation: ^uint64(0)}, ^uint64(0)); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	r := fileRecord(t, p)
	r.Kind = "directory"
	r.MaterializedKind = "directory"
	r.Payload = nil
	if e := s.VerifyPayload(testContext, r); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(m, "manifest.json"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Load(testContext); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	os.Remove(filepath.Join(m, "manifest.json"))
	ref := digest(nil)
	if e := os.Mkdir(filepath.Join(m, blobName(ref)), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := s.PutBlob(testContext, bytes.NewReader(nil), 0); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	s.limits.ManifestBytes = 0
	if e := s.Commit(testContext, Manifest{Version: 1}, 0); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	if e := s.VerifyPayload(testContext, Record{}); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	r.Original = "missing"
	r.Materialized = "missing"
	if e := s.VerifyPayload(testContext, r); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
}

type faultRoot struct {
	carrierRoot
	open     func(string) (*os.File, error)
	openFile func(string, int, os.FileMode) (*os.File, error)
	lstat    func(string) (os.FileInfo, error)
	rename   func(string, string) error
	readlink func(string) (string, error)
}

func (r faultRoot) Open(n string) (*os.File, error) {
	if r.open != nil {
		return r.open(n)
	}
	return r.carrierRoot.Open(n)
}
func (r faultRoot) OpenFile(n string, f int, m os.FileMode) (*os.File, error) {
	if r.openFile != nil {
		return r.openFile(n, f, m)
	}
	return r.carrierRoot.OpenFile(n, f, m)
}
func (r faultRoot) Lstat(n string) (os.FileInfo, error) {
	if r.lstat != nil {
		return r.lstat(n)
	}
	return r.carrierRoot.Lstat(n)
}
func (r faultRoot) Rename(a, b string) error {
	if r.rename != nil {
		return r.rename(a, b)
	}
	return r.carrierRoot.Rename(a, b)
}
func (r faultRoot) Readlink(n string) (string, error) {
	if r.readlink != nil {
		return r.readlink(n)
	}
	return r.carrierRoot.Readlink(n)
}

type modeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (i modeInfo) Mode() os.FileMode { return i.mode }
func (i modeInfo) IsDir() bool       { return i.mode.IsDir() }
func TestCarrierIOFailures(t *testing.T) {
	s, p, _ := fixture(t)
	r := fileRecord(t, p)
	base := s.metadata
	payload := s.payload
	sentinel := errors.New("injected io")
	ref := mustBlob(t, s, []byte("blob"))
	s.metadata = faultRoot{carrierRoot: base, openFile: func(string, int, os.FileMode) (*os.File, error) { return nil, sentinel }}
	if _, e := s.PutBlob(testContext, bytes.NewReader(nil), 0); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if e := s.Commit(testContext, Manifest{Version: 1}, 0); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	s.metadata = faultRoot{carrierRoot: base, rename: func(string, string) error { return sentinel }}
	if _, e := s.PutBlob(testContext, strings.NewReader("new"), 3); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	s.metadata = faultRoot{carrierRoot: base, open: func(string) (*os.File, error) { return nil, sentinel }}
	if _, e := s.OpenBlob(testContext, ref); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	s.metadata = faultRoot{carrierRoot: base, open: func(n string) (*os.File, error) {
		f, e := base.Open(n)
		if e == nil {
			f.Close()
		}
		return f, e
	}}
	if _, e := s.OpenBlob(testContext, ref); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	f, e := base.Open(blobName(ref))
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	// Stat's closed-handle error is platform-specific (ERROR_INVALID_HANDLE
	// on Windows). Verification must propagate that actual native cause.
	_, statErr := f.Stat()
	var statPathError *os.PathError
	if !errors.As(statErr, &statPathError) {
		t.Fatal("expected closed-file stat failure", statErr)
	}
	if e = verify(testContext, f, ref); !errors.Is(e, statPathError.Err) {
		t.Fatal(e)
	}
	s.metadata = base
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	f, e = base.Open(blobName(ref))
	if e != nil {
		t.Fatal(e)
	}
	if e = verify(ctx, f, ref); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	f.Close()
	s.payload = faultRoot{carrierRoot: payload, open: func(string) (*os.File, error) { return nil, sentinel }}
	if e = s.VerifyPayload(testContext, r); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	// Replacement between inspection and open is an identity conflict.
	other := "other"
	os.WriteFile(filepath.Join(p, other), []byte("other"), 0600)
	s.payload = faultRoot{carrierRoot: payload, open: func(string) (*os.File, error) { return payload.Open(other) }}
	if e = s.VerifyPayload(testContext, r); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	s.payload = payload
	// Errors after the manifest lock has been acquired still remove that lock.
	s.metadata = faultRoot{carrierRoot: base, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
		if strings.HasPrefix(n, ".manifest-") {
			return nil, sentinel
		}
		return base.OpenFile(n, flags, mode)
	}}
	if e = s.Commit(testContext, Manifest{Version: 1}, 0); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if _, e = base.Lstat(".lock"); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	s.metadata = faultRoot{carrierRoot: base, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
		f, e := base.OpenFile(n, flags, mode)
		if e == nil && strings.HasPrefix(n, ".manifest-") {
			f.Close()
		}
		return f, e
	}}
	if e = s.Commit(testContext, Manifest{Version: 1}, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	s.metadata = faultRoot{carrierRoot: base, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
		f, e := base.OpenFile(n, flags, mode)
		if e == nil && strings.HasPrefix(n, ".blob-") {
			f.Close()
		}
		return f, e
	}}
	if _, e = s.PutBlob(testContext, bytes.NewReader(nil), 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	s.metadata = base
	// Missing blobs cannot publish a manifest even if the reference is well formed.
	missing := digest([]byte("missing"))
	r.Attributes = []Attribute{{"x", missing}}
	if e = s.Commit(testContext, Manifest{Version: 1, Records: []Record{r}}, 0); !errors.Is(e, ErrCorrupt) {
		t.Fatal(e)
	}
	badTime := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	r.Attributes = nil
	r.Darwin.Birth = &badTime
	if e = s.Commit(testContext, Manifest{Version: 1, Records: []Record{r}}, 0); e == nil {
		t.Fatal("invalid time")
	}
}
func TestCarrierLinkAndParentPolicies(t *testing.T) {
	s, p, _ := fixture(t)
	file := fileRecord(t, p)
	base := s.payload
	info, e := base.Lstat("file")
	if e != nil {
		t.Fatal(e)
	}
	link := Record{Original: "link", Materialized: "link", Kind: "symlink", MaterializedKind: "symlink", Target: "target"}
	s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return modeInfo{info, os.ModeSymlink}, nil }, readlink: func(string) (string, error) { return "target", nil }}
	if e = s.VerifyPayload(testContext, link); e != nil {
		t.Fatal(e)
	}
	s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return info, nil }}
	if e = s.VerifyPayload(testContext, link); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return modeInfo{info, os.ModeSymlink}, nil }, readlink: func(string) (string, error) { return "wrong", nil }}
	if e = s.VerifyPayload(testContext, link); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	sentinel := errors.New("readlink failed")
	s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return modeInfo{info, os.ModeSymlink}, nil }, readlink: func(string) (string, error) { return "", sentinel }}
	if e = s.VerifyPayload(testContext, link); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	file.Materialized = "parent/file"
	s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return modeInfo{info, os.ModeDir | os.ModeSymlink}, nil }}
	if e = s.VerifyPayload(testContext, file); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e = openRegular(s.payload, file.Materialized); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	s.payload = base
	if e = s.VerifyPayload(testContext, file); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	os.Mkdir(filepath.Join(p, "parent"), 0700)
	os.WriteFile(filepath.Join(p, "parent", "file"), []byte("payload"), 0600)
	if e = s.VerifyPayload(testContext, file); e != nil {
		t.Fatal(e)
	}
}

func TestCarrierAttributes(t *testing.T) {
	s, _, _ := fixture(t)
	want := map[string][]byte{"empty": {}, "raw\xff": {1, 2}, "Case": {4}, "case": {5}}
	attrs, e := s.StoreAttributes(testContext, want)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := json.Marshal(attrs)
	if e != nil {
		t.Fatal(e)
	}
	var decoded []Attribute
	if e = json.Unmarshal(encoded, &decoded); e != nil {
		t.Fatal(e)
	}
	got, e := s.ReadAttributes(testContext, decoded, 4)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%v != %v", want, got)
	}
	if _, e = s.ReadAttributes(testContext, decoded, 3); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	merged, e := MergeAttributes(map[string][]byte{"empty": nil, "native": {9}}, got)
	if e != nil || merged["empty"] == nil {
		t.Fatal(e)
	}
	merged["case"][0] = 10
	if got["case"][0] != 5 {
		t.Fatal("alias")
	}
	if _, e = MergeAttributes(map[string][]byte{"case": {10}}, got); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	for _, b := range []string{`{"nameBytes":"%%%","value":{}}`, `{"nameBytes":"YQ==","unknown":1}`, `{} {}`} {
		var a Attribute
		if e = a.UnmarshalJSON([]byte(b)); e == nil {
			t.Fatal(b)
		}
	}
	if _, e = s.StoreAttributes(nil, nil); !errors.Is(e, fs.ErrInvalid) { //nolint:staticcheck // Exercise rejection of an invalid context.
		t.Fatal(e)
	}
	if _, e = s.ReadAttributes(nil, nil, 0); !errors.Is(e, fs.ErrInvalid) { //nolint:staticcheck // Exercise rejection of an invalid context.
		t.Fatal(e)
	}
	if _, e = s.ReadAttributes(testContext, nil, -1); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	for _, a := range [][]Attribute{{{Name: ""}}, {{Name: "a", Value: BlobRef{}}}, {{Name: "a", Value: digest(nil)}, {Name: "a", Value: digest(nil)}}} {
		if _, e = s.ReadAttributes(testContext, a, 10); !errors.Is(e, ErrInvalid) {
			t.Fatal(e)
		}
	}
	if _, e = s.StoreAttributes(testContext, map[string][]byte{"": {}}); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	if _, e = s.StoreAttributes(cancelled, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = s.ReadAttributes(cancelled, nil, 0); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	s.limits.Attributes = 0
	if _, e = s.StoreAttributes(testContext, want); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	if _, e = s.ReadAttributes(testContext, attrs, 4); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	if _, e = s.Load(nil); !errors.Is(e, fs.ErrInvalid) { //nolint:staticcheck // Exercise rejection of an invalid context.
		t.Fatal(e)
	}
	s.limits = DefaultLimits()
	if _, e = s.StoreAttributes(testContext, map[string][]byte{"too-big": nil}); e != nil {
		t.Fatal(e)
	}
	s.limits.BlobBytes = 0
	if _, e = s.StoreAttributes(testContext, map[string][]byte{"too-big": {1}}); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	if _, e = s.ReadAttributes(testContext, []Attribute{{Name: "missing", Value: digest([]byte{9})}}, 10); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
}
func FuzzCarrierManifest(f *testing.F) {
	for _, b := range []string{`{"version":1,"generation":1,"records":[]}`, `{"a":1,"a":2}`, `[[null]]`} {
		f.Add([]byte(b))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_ = uniqueJSON(b)
	})
}

func TestRecordAttributeRepresentations(t *testing.T) {
	s, _, m := fixture(t)
	values := map[string][]byte{"user.a": {1}, appledouble.FinderInfoName: make([]byte, 32), appledouble.ResourceForkName: {2, 3}}
	attrs, e := s.StoreAttributes(testContext, values)
	if e != nil {
		t.Fatal(e)
	}
	ad, e := appledouble.FromXattrs(values).Encode()
	if e != nil {
		t.Fatal(e)
	}
	ref := mustBlob(t, s, ad)
	r := Record{Attributes: attrs, AppleDouble: &ref}
	got, e := s.ReadRecordAttributes(testContext, r, 35)
	if e != nil || !reflect.DeepEqual(values, got) {
		t.Fatal(e)
	}
	security := mustBlob(t, s, []byte{4})
	r.Darwin.Security = &security
	got, e = s.ReadRecordAttributes(testContext, r, 36)
	if e != nil || !bytes.Equal(got["com.apple.system.Security"], []byte{4}) {
		t.Fatal(e)
	}
	if _, e = s.ReadRecordAttributes(testContext, r, 35); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	if _, e = s.ReadRecordAttributes(testContext, r, 0); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	other := mustBlob(t, s, []byte("different"))
	r.AppleDouble = &other
	if _, e = s.ReadRecordAttributes(testContext, r, 100); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	r.AppleDouble = &ref
	r.Attributes = attrsCarrierForTest(t, s, map[string][]byte{appledouble.FinderInfoName: {1}})
	if _, e = s.ReadRecordAttributes(testContext, r, 100); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	r.Attributes = attrsCarrierForTest(t, s, map[string][]byte{"invalid\xff": {1}})
	if _, e = s.ReadRecordAttributes(testContext, r, 100); e == nil {
		t.Fatal("invalid sidecar namespace")
	}
	r.Attributes = attrs
	r.Darwin.Security = nil
	os.Remove(filepath.Join(m, blobName(ref)))
	if _, e = s.ReadRecordAttributes(testContext, r, 100); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	r.AppleDouble = nil
	r.Attributes = attrsCarrierForTest(t, s, map[string][]byte{"com.apple.system.Security": {4}})
	r.Darwin.Security = &security
	if _, e = s.ReadRecordAttributes(testContext, r, 1); e != nil {
		t.Fatal(e)
	}
}
func attrsCarrierForTest(t *testing.T, s *Store, values map[string][]byte) []Attribute {
	t.Helper()
	a, e := s.StoreAttributes(testContext, values)
	if e != nil {
		t.Fatal(e)
	}
	return a
}

func TestNativeBaselineReconciliation(t *testing.T) {
	s, p, _ := fixture(t)
	r := fileRecord(t, p)
	r.NativeAttributes = attrsCarrierForTest(t, s, map[string][]byte{"automatic": {1}, "same": {2}})
	r.NativeCaptured = true
	r.Attributes = attrsCarrierForTest(t, s, map[string][]byte{"logical": {}, "same": {2}})
	if e := s.Commit(testContext, Manifest{Version: 1, Records: []Record{r}}, 0); e != nil {
		t.Fatal(e)
	}
	loaded, e := s.Load(testContext)
	if e != nil || !loaded.Records[0].NativeCaptured {
		t.Fatal(e)
	}
	baseline, e := s.ReadNativeBaseline(testContext, r, 10)
	if e != nil {
		t.Fatal(e)
	}
	logical, e := s.ReadRecordAttributes(testContext, r, 10)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ReconcileAttributes(map[string][]byte{"automatic": {1}, "same": {2}, "new": {3}}, baseline, logical)
	if e != nil || got["automatic"] != nil || got["logical"] == nil || !bytes.Equal(got["new"], []byte{3}) {
		t.Fatal(got, e)
	}
	got, e = ReconcileAttributes(map[string][]byte{"automatic": {4}, "same": {2}}, baseline, logical)
	if e != nil || !bytes.Equal(got["automatic"], []byte{4}) {
		t.Fatal(got, e)
	}
	if _, e = ReconcileAttributes(map[string][]byte{"same": {9}}, baseline, logical); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if _, e = ReconcileAttributes(nil, baseline, logical); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	r.NativeUnsupported = true
	if e = s.validate(Manifest{Version: 1, Records: []Record{r}}); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e = s.ReadNativeBaseline(testContext, r, 10); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	r.NativeCaptured = false
	if e = s.validate(Manifest{Version: 1, Records: []Record{r}}); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	r.NativeAttributes = nil
	if _, e = s.ReadNativeBaseline(testContext, r, 0); e != nil {
		t.Fatal(e)
	}
	//nolint:staticcheck // Verify that a missing context is rejected.
	if _, e = s.ReadNativeBaseline(nil, r, 0); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	} //nolint:staticcheck // Intentional invalid context.
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	if _, e = s.ReadNativeBaseline(cancelled, r, 0); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestRecordSecurityConflict(t *testing.T) {
	s, _, _ := fixture(t)
	r := Record{Attributes: attrsCarrierForTest(t, s, map[string][]byte{"com.apple.system.Security": {1}})}
	other := mustBlob(t, s, []byte{2})
	r.Darwin.Security = &other
	if _, e := s.ReadRecordAttributes(testContext, r, 1); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	s.Close()
	if _, e := s.StoreAttributes(testContext, nil); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if _, e := s.ReadAttributes(testContext, nil, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
}
