package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

type carrierVolume struct {
	fstest.MapFS
	attrs   map[string][]byte
	failure error
}

func (v carrierVolume) Readlink(n string) (string, error) {
	f, ok := v.MapFS[n]
	if !ok {
		return "", fs.ErrNotExist
	}
	return string(f.Data), nil
}
func (v carrierVolume) Xattrs(string) (map[string][]byte, error) { return v.attrs, v.failure }
func (v carrierVolume) Metadata(string) (hostdata.ImageMetadata, error) {
	return hostdata.ImageMetadata{UID: 501, GID: 20, Mode: 0640, Times: &hostdata.FileTimes{Birth: time.Unix(1, 0), Modify: time.Unix(2, 0), Change: time.Unix(3, 0), Access: time.Unix(4, 0)}}, v.failure
}
func newCarrierExtractor(t *testing.T, v VolumeFS) *Extractor {
	t.Helper()
	base := t.TempDir()
	e := NewExtractor(v, filepath.Join(base, "payload"))
	e.MetadataRoot = filepath.Join(base, "metadata")
	return e
}
func sampleCarrierVolume() carrierVolume {
	return carrierVolume{MapFS: fstest.MapFS{
		".": {Mode: fs.ModeDir | 0755}, "folder": {Mode: fs.ModeDir | 0755}, "folder/A": {Data: []byte("one")}, "folder/a": {Data: []byte("two")}, "folder/日本": {Data: []byte("three")}, "folder/CON": {Data: []byte("four")}, "folder/link": {Mode: fs.ModeSymlink, Data: []byte("A")}, "._real": {Data: []byte("ordinary")},
	}, attrs: map[string][]byte{"com.apple.example": []byte("metadata"), "empty": {}}}
}

func TestCarrierExtraction(t *testing.T) {
	v := sampleCarrierVolume()
	e := newCarrierExtractor(t, v)
	e.Xattrs = true
	e.PreserveMeta = true
	e.VerifyChecksum = true
	e.SymlinkMode = SymlinkFile
	if err := e.ExtractAll(); err != nil {
		t.Fatal(err)
	}
	store, err := metatransport.Open(e.Destination, e.MetadataRoot, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Records) != 8 {
		t.Fatalf("records %d", len(m.Records))
	}
	for _, r := range m.Records {
		if err := store.VerifyPayload(context.Background(), r); err != nil {
			t.Fatalf("%s: %v", r.Original, err)
		}
		attrs, err := store.ReadAttributes(context.Background(), r.Attributes, 10000)
		if err != nil || string(attrs["com.apple.example"]) != "metadata" {
			t.Fatalf("%v %v", attrs, err)
		}
		if r.AppleDouble == nil || r.Darwin.UID == nil || *r.Darwin.UID != 501 || r.Darwin.Change == nil || r.Darwin.Change.Unix() != 3 {
			t.Fatalf("metadata %+v", r)
		}
		if r.Original == "folder/link" && (r.Kind != "symlink" || r.MaterializedKind != "file" || r.Target != "A") {
			t.Fatalf("link %+v", r)
		}
	}
	if e.namesRemapped < 3 || e.symlinksDegraded != 1 || e.xattrsCarried != 16 {
		t.Fatalf("stats %+v", e)
	}
	if err := e.VerifyExtractedFiles(); err != nil {
		t.Fatal(err)
	}
	if err := e.ExtractAll(); err == nil {
		t.Fatal("existing destination overwritten")
	}
}

func TestCarrierNames(t *testing.T) {
	used := map[string]bool{}
	for _, name := range []string{"a", "A", "a", "CON", "with:colon", "日本", strings.Repeat("x", 300), "._actual"} {
		got := carrierName(name, used)
		if got == "" || len(got) > 160 || strings.ContainsAny(got, ":\\") {
			t.Fatalf("%q => %q", name, got)
		}
	}
}

func TestCarrierExtractionErrors(t *testing.T) {
	v := sampleCarrierVolume()
	e := newCarrierExtractor(t, v)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.Context = ctx
	if err := e.ExtractAll(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	e = newCarrierExtractor(t, carrierVolume{MapFS: fstest.MapFS{"fifo": {Mode: fs.ModeNamedPipe}}})
	if err := e.ExtractAll(); err == nil {
		t.Fatal("special file accepted")
	}
	e = newCarrierExtractor(t, v)
	e.MetadataRoot = e.Destination
	if err := e.ExtractAll(); err == nil {
		t.Fatal("overlapping roots accepted")
	}
	e = newCarrierExtractor(t, v)
	e.Xattrs = true
	v.failure = errors.New("source read")
	e.Volume = v
	if err := e.ExtractAll(); !errors.Is(err, v.failure) {
		t.Fatal(err)
	}
	e = newCarrierExtractor(t, v)
	e.PreserveMeta = true
	if err := e.ExtractAll(); !errors.Is(err, v.failure) {
		t.Fatal(err)
	}
	e = newCarrierExtractor(t, sampleCarrierVolume())
	zero := metatransport.Limits{}
	e.MetadataLimits = &zero
	e.Xattrs = true
	if err := e.ExtractAll(); !errors.Is(err, metatransport.ErrLimit) {
		t.Fatal(err)
	}
	e = newCarrierExtractor(t, sampleCarrierVolume())
	if err := e.ExtractByPath("/folder", false); err == nil {
		t.Fatal("nonrecursive directory")
	}
	if err := e.ExtractByPath("/folder/A", false); err != nil {
		t.Fatal(err)
	}
}

type carrierReadCloser struct{ err error }

func (c carrierReadCloser) Read([]byte) (int, error) { return 0, c.err }
func (c carrierReadCloser) Close() error             { return c.err }
func TestCarrierPayloadFailures(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fault := errors.New("read/close failed")
	if _, err := writeCarrierPayload(context.Background(), root, "payload", carrierReadCloser{fault}); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := writeCarrierPayload(context.Background(), root, "payload", io.NopCloser(bytes.NewReader(nil))); !errors.Is(err, fs.ErrExist) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writeCarrierPayload(ctx, root, "canceled", io.NopCloser(bytes.NewReader([]byte("data")))); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type carrierPlainVolume struct{ fstest.MapFS }

func (v carrierPlainVolume) Readlink(string) (string, error) { return "", fs.ErrInvalid }

type carrierFaultVolume struct {
	carrierVolume
	openErr, errorAtInfo, readDirErr error
	cancel                           context.CancelFunc
	targetErr                        error
}

func (v carrierFaultVolume) Open(n string) (fs.File, error) {
	if v.cancel != nil {
		v.cancel()
	}
	if v.openErr != nil && n != "." {
		return nil, v.openErr
	}
	return v.carrierVolume.Open(n)
}
func (v carrierFaultVolume) Readlink(n string) (string, error) {
	if v.targetErr != nil {
		return "", v.targetErr
	}
	return v.carrierVolume.Readlink(n)
}

func TestCarrierPreflightAndStorageFailures(t *testing.T) {
	ctx := context.Background()
	v := sampleCarrierVolume()
	e := newCarrierExtractor(t, carrierPlainVolume{v.MapFS})
	e.Xattrs = true
	if err := e.ExtractAll(); err == nil {
		t.Fatal("unknown xattrs accepted")
	}
	e = newCarrierExtractor(t, carrierPlainVolume{v.MapFS})
	e.PreserveMeta = true
	if err := e.ExtractAll(); err == nil {
		t.Fatal("unknown metadata accepted")
	}
	e = newCarrierExtractor(t, v)
	if err := os.WriteFile(e.Destination, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.ExtractAll(); err == nil {
		t.Fatal("payload file accepted as directory")
	}
	e = newCarrierExtractor(t, v)
	if err := os.WriteFile(e.MetadataRoot, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.ExtractAll(); err == nil {
		t.Fatal("metadata file accepted as directory")
	}
	e = newCarrierExtractor(t, v)
	if err := os.MkdirAll(e.MetadataRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.MetadataRoot, "manifest.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.ExtractAll(); err == nil {
		t.Fatal("corrupt carrier accepted")
	}
	e = newCarrierExtractor(t, v)
	if err := os.MkdirAll(e.Destination, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.MetadataRoot, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := metatransport.Open(e.Destination, e.MetadataRoot, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, metatransport.Manifest{Version: 1}, 0); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if err := e.ExtractAll(); !errors.Is(err, metatransport.ErrConflict) {
		t.Fatal(err)
	}
	fault := errors.New("injected source failure")
	e = newCarrierExtractor(t, carrierFaultVolume{carrierVolume: v, openErr: fault})
	if err := e.ExtractAll(); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	e = newCarrierExtractor(t, carrierFaultVolume{carrierVolume: v, targetErr: fault})
	if err := e.ExtractAll(); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	e = newCarrierExtractor(t, v)
	e.Xattrs = true
	e.MetadataLimits = &metatransport.Limits{ManifestBytes: 10000, BlobBytes: 0, Records: 100, Attributes: 100}
	if err := e.ExtractAll(); !errors.Is(err, metatransport.ErrLimit) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	e = newCarrierExtractor(t, carrierFaultVolume{carrierVolume: v, cancel: cancel})
	e.Context = canceled
	if err := e.ExtractAll(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	e = newCarrierExtractor(t, v)
	e.PreserveMeta = true
	if err := e.ExtractByPath("/folder/A", false); err != nil {
		t.Fatal(err)
	}
	if e.XattrsCarried() != 0 {
		t.Fatal("unselected attributes stored")
	}
}

func TestCarrierAttributeRepresentations(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	payload := filepath.Join(base, "payload")
	metadata := filepath.Join(base, "metadata")
	if err := os.Mkdir(payload, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(metadata, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := metatransport.Open(payload, metadata, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, attrs := range []map[string][]byte{nil, {"com.apple.FinderInfo": make([]byte, 32), "com.apple.ResourceFork": []byte("fork")}, {strings.Repeat("x", 128): []byte("value")}, {"com.apple.FinderInfo": {1}}, {string([]byte{255}): {1}}} {
		got, _, err := storeCarrierAttrs(ctx, store, attrs)
		if err != nil || len(got) != len(attrs) {
			t.Fatalf("%d %v", len(got), err)
		}
	}
	// A large valid entry table may exceed AppleDouble's wire header while the
	// raw carrier still represents every original attribute.
	many := map[string][]byte{}
	for i := 0; i < 600; i++ {
		many[fmt.Sprintf("user.%0110d", i)] = nil
	}
	got, sidecar, err := storeCarrierAttrs(ctx, store, many)
	if err != nil || sidecar != nil || len(got) != 600 {
		t.Fatalf("header: %d %v %v", len(got), sidecar, err)
	}
	t.Setenv("TMPDIR", filepath.Join(base, "missing"))
	t.Setenv("TMP", filepath.Join(base, "missing"))
	t.Setenv("TEMP", filepath.Join(base, "missing"))
	if _, _, err := storeCarrierAttrs(ctx, store, map[string][]byte{"user.value": {1}}); err == nil {
		t.Fatal("missing temporary directory")
	}
}

type carrierFaultEntry struct {
	fs.DirEntry
	failure error
}

func (e carrierFaultEntry) Info() (fs.FileInfo, error) { return nil, e.failure }
func (v carrierFaultVolume) ReadDir(n string) ([]fs.DirEntry, error) {
	if v.readDirErr != nil {
		return nil, v.readDirErr
	}
	entries, e := v.carrierVolume.ReadDir(n)
	if e != nil {
		return nil, e
	}
	if v.errorAtInfo != nil && len(entries) > 0 {
		entries[0] = carrierFaultEntry{entries[0], v.errorAtInfo}
	}
	return entries, nil
}

type linkedCarrierVolume struct{ carrierVolume }

func (v linkedCarrierVolume) Metadata(n string) (hostdata.ImageMetadata, error) {
	m, e := v.carrierVolume.Metadata(n)
	if n != "." {
		m.LinkID = 17
	}
	return m, e
}
func TestCarrierControlledExtractionFailures(t *testing.T) {
	sentinel := errors.New("injected operation failure")
	for _, which := range []string{"source-directory", "source-info", "unknown-xattrs", "unknown-meta", "destination-directory", "destination-open", "closed-parent", "cancel-after-open", "native-unsupported", "native-failure", "native-budget", "manifest-budget", "source-links", "symlink-auto"} {
		t.Run(which, func(t *testing.T) {
			v := carrierVolume{MapFS: fstest.MapFS{".": {Mode: fs.ModeDir | 0755}, "file": {Data: []byte("payload")}}}
			e := newCarrierExtractor(t, v)
			e.SymlinkMode = SymlinkFile
			ops := carrierExtractionOps{os.ReadDir, os.OpenRoot, func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
				return map[string]appledouble.Value{}, nil
			}}
			switch which {
			case "source-directory":
				e.Volume = carrierFaultVolume{carrierVolume: v, readDirErr: sentinel}
			case "source-info":
				e.Volume = carrierFaultVolume{carrierVolume: v, errorAtInfo: sentinel}
			case "unknown-xattrs":
				e.Volume = carrierPlainVolume{v.MapFS}
				e.Xattrs = true
			case "unknown-meta":
				e.Volume = carrierPlainVolume{v.MapFS}
				e.PreserveMeta = true
			case "destination-directory":
				ops.readDir = func(string) ([]os.DirEntry, error) { return nil, sentinel }
			case "destination-open":
				ops.openRoot = func(string) (*os.Root, error) { return nil, sentinel }
			case "closed-parent":
				ops.openRoot = func(p string) (*os.Root, error) {
					r, err := os.OpenRoot(p)
					if err == nil {
						r.Close()
					}
					return r, err
				}
			case "cancel-after-open":
				ctx, cancel := context.WithCancel(context.Background())
				e.Context = ctx
				ops.openRoot = func(p string) (*os.Root, error) { r, err := os.OpenRoot(p); cancel(); return r, err }
			case "native-unsupported":
				ops.capture = func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
					return nil, hostdata.ErrXattrUnsupported
				}
			case "native-failure":
				ops.capture = func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
					return nil, sentinel
				}
			case "native-budget":
				limits := metatransport.DefaultLimits()
				limits.BlobBytes = 0
				e.MetadataLimits = &limits
				ops.capture = func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
					return map[string]appledouble.Value{"x": bytes.NewReader([]byte{1})}, nil
				}
			case "manifest-budget":
				limits := metatransport.DefaultLimits()
				limits.ManifestBytes = 0
				e.MetadataLimits = &limits
			case "source-links":
				e.Volume = linkedCarrierVolume{v}
				e.PreserveMeta = true
				limits := hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize}
				e.NativeCaptureLimits = &limits
			case "symlink-auto":
				v.MapFS["link"] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("file")}
				e.Volume = v
				e.SymlinkMode = SymlinkAuto
			}
			err := e.extractCarrierUsing(".", "", ops)
			success := which == "native-unsupported" || which == "source-links" || which == "symlink-auto"
			if success {
				if err != nil {
					t.Fatal(err)
				}
				s, err := metatransport.Open(e.Destination, e.MetadataRoot, metatransport.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				m, err := s.Load(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if which == "native-unsupported" && !m.Records[0].NativeUnsupported {
					t.Fatal(m)
				}
				if which == "source-links" && m.Records[1].LinkGroup != "17" {
					t.Fatal(m)
				}
			} else {
				if err == nil {
					t.Fatal("unexpected success")
				}
				if _, err = os.Stat(filepath.Join(e.MetadataRoot, "manifest.json")); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("failed operation published", err)
				}
			}
		})
	}
}
func TestCarrierPatternAndLateParentFailure(t *testing.T) {
	e := newCarrierExtractor(t, sampleCarrierVolume())
	e.Pattern = regexp.MustCompile(`never-matches`)
	entries, err := e.planCarrier(".", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.info.Mode().IsRegular() {
			t.Fatal("filter ignored")
		}
	}
	e = newCarrierExtractor(t, carrierVolume{MapFS: fstest.MapFS{"file": {Data: []byte("data")}}})
	ops := carrierExtractionOps{os.ReadDir, func(p string) (*os.Root, error) {
		r, err := os.OpenRoot(p)
		if err == nil {
			r.Close()
		}
		return r, err
	}, hostdata.CaptureXattrValuesAt}
	if err = e.extractCarrierUsing("file", "file", ops); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

type carrierWriterFault struct {
	buffer            bytes.Buffer
	syncErr, closeErr error
	short             bool
}

func (w *carrierWriterFault) Write(b []byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return w.buffer.Write(b)
}
func (w *carrierWriterFault) Sync() error  { return w.syncErr }
func (w *carrierWriterFault) Close() error { return w.closeErr }
func TestCarrierPayloadSyncAndClose(t *testing.T) {
	sentinel := errors.New("disk failure")
	for _, which := range []string{"sync", "close", "short"} {
		t.Run(which, func(t *testing.T) {
			w := &carrierWriterFault{}
			want := sentinel
			switch which {
			case "sync":
				w.syncErr = sentinel
			case "close":
				w.closeErr = sentinel
			case "short":
				w.short = true
				want = io.ErrShortWrite
			}
			_, err := writeCarrierPayloadUsing(context.Background(), "file", io.NopCloser(strings.NewReader("data")), func(string) (carrierPayloadFile, error) { return w, nil })
			if !errors.Is(err, want) {
				t.Fatal(err)
			}
		})
	}
}

type streamCarrierVolume struct {
	carrierVolume
	values map[string]appledouble.Value
}

func (v streamCarrierVolume) XattrValues(string) (map[string]appledouble.Value, error) {
	return v.values, nil
}

type transportTestValue struct {
	size           int64
	reads, maxRead int
	failAfter      int
	fault          error
}

func (v *transportTestValue) Size() int64 { return v.size }
func (v *transportTestValue) ReadAt(p []byte, off int64) (int, error) {
	v.reads++
	if len(p) > v.maxRead {
		v.maxRead = len(p)
	}
	if v.failAfter > 0 && v.reads >= v.failAfter {
		return 0, v.fault
	}
	if off >= v.size {
		return 0, io.EOF
	}
	n := min(int64(len(p)), v.size-off)
	for i := range p[:n] {
		p[i] = byte((off + int64(i)) % 251)
	}
	if n < int64(len(p)) {
		return int(n), io.EOF
	}
	return int(n), nil
}
func TestCarrierStreamingSource(t *testing.T) {
	large := &transportTestValue{size: 17 << 20}
	v := streamCarrierVolume{carrierVolume: carrierVolume{MapFS: fstest.MapFS{"file": {Data: []byte("payload")}}, failure: errors.New("byte API must not be used")}, values: map[string]appledouble.Value{"user.large": large, "empty": nil}}
	e := newCarrierExtractor(t, v)
	e.Xattrs = true
	if err := e.ExtractAll(); err != nil {
		t.Fatal(err)
	}
	if large.maxRead > 64<<10 || large.reads < 200 {
		t.Fatalf("not bounded streaming: %+v", large)
	}
	if e.XattrsCarried() != 4 {
		t.Fatal(e.XattrsCarried())
	}
}
func TestCarrierStreamingFinderReadFailures(t *testing.T) {
	base := t.TempDir()
	payload := filepath.Join(base, "payload")
	metadata := filepath.Join(base, "metadata")
	os.Mkdir(payload, 0700)
	os.Mkdir(metadata, 0700)
	store, err := metatransport.Open(payload, metadata, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fault := errors.New("read failed after blob")
	value := &transportTestValue{size: 32, failAfter: 2, fault: fault}
	if _, _, err := storeCarrierValues(context.Background(), store, map[string]appledouble.Value{appledouble.FinderInfoName: value}); !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, fault) {
		t.Fatal(err)
	}
}

func TestCarrierInitialBaselineStreamsValues(t *testing.T) {
	value := &transportTestValue{size: 17 << 20}
	e := newCarrierExtractor(t, carrierVolume{MapFS: fstest.MapFS{"file": {Data: []byte("payload")}}})
	e.NativeCaptureLimits = &hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize, ValueBytes: 16, TotalBytes: 16}
	captured := 0
	ops := carrierExtractionOps{os.ReadDir, os.OpenRoot, func(ctx context.Context, root *os.Root, name string, limits hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
		if root == nil || limits.ValueBytes != 16 {
			t.Fatal("capture lost held root or explicit limits")
		}
		if name != "file" {
			return nil, nil
		}
		f, err := root.Open(name)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(f)
		err = errors.Join(err, f.Close())
		if err != nil {
			return nil, err
		}
		if string(data) != "payload" {
			t.Fatal("capture did not refer to extracted entry")
		}
		captured++
		return map[string]appledouble.Value{hostdata.ResourceForkName: value}, ctx.Err()
	}}
	if err := e.extractCarrierUsing(".", "", ops); err != nil {
		t.Fatal(err)
	}
	if captured != 1 || value.reads < 200 || value.maxRead > 64<<10 {
		t.Fatal(captured, value)
	}
	store, err := metatransport.Open(e.Destination, e.MetadataRoot, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manifest, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range manifest.Records {
		if record.Original != "file" {
			continue
		}
		if !record.NativeCaptured || len(record.NativeAttributes) != 1 || record.NativeAttributes[0].Value.Size != value.Size() {
			t.Fatal(record)
		}
		values, err := store.BorrowAttributes(context.Background(), record.NativeAttributes)
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, 17)
		offset := value.Size() - int64(len(data))
		if _, err := values[hostdata.ResourceForkName].ReadAt(data, offset); err != nil {
			t.Fatal(err)
		}
		for i, b := range data {
			if b != byte((offset+int64(i))%251) {
				t.Fatal("baseline data changed")
			}
		}
		found = true
	}
	if !found {
		t.Fatal("native baseline missing")
	}
}

func TestCarrierSourceAttributeObservation(t *testing.T) {
	for _, capture := range []bool{false, true} {
		t.Run(fmt.Sprint(capture), func(t *testing.T) {
			v := sampleCarrierVolume()
			v.attrs = nil
			e := newCarrierExtractor(t, v)
			e.Xattrs = capture
			e.SymlinkMode = SymlinkFile
			if err := e.ExtractAll(); err != nil {
				t.Fatal(err)
			}
			store, err := metatransport.Open(e.Destination, e.MetadataRoot, metatransport.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			manifest, err := store.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range manifest.Records {
				if record.SourceAttributesCaptured != capture {
					t.Fatalf("source observation %s=%t want %t", record.Original, record.SourceAttributesCaptured, capture)
				}
				value, observed, err := store.ObservedSourceAttribute(t.Context(), record, "com.apple.system.Security")
				if err != nil || observed != capture || value != nil {
					t.Fatal(record.Original, value, observed, err)
				}
			}
		})
	}
	// A failed enumeration cannot publish even an apparently empty captured set.
	v := sampleCarrierVolume()
	v.failure = errors.New("incomplete source enumeration")
	e := newCarrierExtractor(t, v)
	e.Xattrs = true
	if err := e.ExtractAll(); !errors.Is(err, v.failure) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.MetadataRoot, "manifest.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("failed extraction published source observations", err)
	}
}
