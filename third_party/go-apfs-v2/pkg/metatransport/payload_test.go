package metatransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type payloadStatFunc func() (os.FileInfo, error)

func (f payloadStatFunc) Stat() (os.FileInfo, error) { return f() }

type payloadCleanupRoot struct {
	carrierRoot
	remove func(string) error
}

func (r payloadCleanupRoot) Remove(name string) error {
	if r.remove != nil {
		return r.remove(name)
	}
	return r.carrierRoot.Remove(name)
}

func TestCarrierPayloadOpenAndAssociation(t *testing.T) {
	s, p, _ := fixture(t)
	r := fileRecord(t, p)
	file, err := s.OpenPayload(t.Context(), r.Materialized)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = s.CheckPayload(t.Context(), r.Materialized, file); err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("edited!"), 0); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(p, r.Materialized))
	if err != nil || string(data) != "edited!" {
		t.Fatal(string(data), err)
	}
	// Association is an identity check, not an implicit content-baseline check.
	if err = s.CheckPayload(t.Context(), r.Materialized, file); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifyPayload(t.Context(), r); !errors.Is(err, ErrConflict) {
		t.Fatal("changed bytes accepted against old baseline", err)
	}
	if err = os.WriteFile(filepath.Join(p, "other"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckPayload(t.Context(), "other", file); !errors.Is(err, ErrConflict) {
		t.Fatal("equal bytes substituted another inode", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	// The payload handle belongs to the caller, independently of Store lifetime.
	if _, err = file.Stat(); err != nil {
		t.Fatal("Store closed caller-owned payload", err)
	}
	if err = s.CheckPayload(t.Context(), r.Materialized, file); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if other, err := s.OpenPayload(t.Context(), r.Materialized); other != nil || !errors.Is(err, os.ErrClosed) {
		t.Fatal(other, err)
	}
}

func TestCarrierPayloadOpenFailures(t *testing.T) {
	failure := errors.New("payload acquisition failure")
	for _, scenario := range []string{"invalid", "cancelled", "parent", "lstat", "directory", "open", "closed-handle", "different-inode", "opened-directory"} {
		t.Run(scenario, func(t *testing.T) {
			s, p, _ := fixture(t)
			r := fileRecord(t, p)
			base := s.payload
			ctx := t.Context()
			name := r.Materialized
			want := failure
			switch scenario {
			case "invalid":
				name = "../outside"
				want = ErrInvalid
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "parent":
				name = "redirect/file"
				s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return nil, failure }}
			case "lstat":
				s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return nil, failure }}
			case "directory":
				if err := os.Mkdir(filepath.Join(p, "directory"), 0700); err != nil {
					t.Fatal(err)
				}
				name = "directory"
				want = ErrConflict
			case "open":
				s.payload = faultRoot{carrierRoot: base, openFile: func(string, int, os.FileMode) (*os.File, error) { return nil, failure }}
			case "closed-handle":
				want = os.ErrClosed
				s.payload = faultRoot{carrierRoot: base, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
					file, err := base.OpenFile(n, flags, mode)
					if err == nil {
						err = file.Close()
					}
					return file, err
				}}
			case "different-inode":
				want = ErrConflict
				if err := os.WriteFile(filepath.Join(p, "different"), []byte("payload"), 0600); err != nil {
					t.Fatal(err)
				}
				s.payload = faultRoot{carrierRoot: base, openFile: func(string, int, os.FileMode) (*os.File, error) { return base.OpenFile("different", os.O_RDWR, 0) }}
			case "opened-directory":
				want = ErrConflict
				s.payload = faultRoot{carrierRoot: base, openFile: func(string, int, os.FileMode) (*os.File, error) { return base.Open(".") }}
			}
			var acquired *os.File
			root := s.payload
			s.payload = faultRoot{carrierRoot: root, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
				f, e := root.OpenFile(n, flags, mode)
				acquired = f
				return f, e
			}}
			file, err := s.OpenPayload(ctx, name)
			if file != nil || !errors.Is(err, want) {
				t.Fatal(file, err, want)
			}
			if acquired != nil {
				if e := acquired.Close(); !errors.Is(e, os.ErrClosed) {
					t.Fatal("rejected acquired handle leaked", e)
				}
			}
		})
	}
}

func TestCarrierPayloadCheckFailures(t *testing.T) {
	failure := errors.New("payload association failure")
	for _, scenario := range []string{"invalid", "nil-file", "cancelled", "parent", "lstat", "stat", "current-directory", "held-directory", "different-inode"} {
		t.Run(scenario, func(t *testing.T) {
			s, p, _ := fixture(t)
			r := fileRecord(t, p)
			base := s.payload
			file, err := s.OpenPayload(t.Context(), r.Materialized)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var held interface{ Stat() (os.FileInfo, error) } = file
			ctx := t.Context()
			name := r.Materialized
			want := failure
			switch scenario {
			case "invalid":
				name = "../outside"
				want = ErrInvalid
			case "nil-file":
				held = nil
				want = ErrInvalid
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "parent":
				name = "redirect/file"
				s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return nil, failure }}
			case "lstat":
				s.payload = faultRoot{carrierRoot: base, lstat: func(string) (os.FileInfo, error) { return nil, failure }}
			case "stat":
				held = payloadStatFunc(func() (os.FileInfo, error) { return nil, failure })
			case "current-directory":
				name = "."
				want = ErrConflict
			case "held-directory":
				held = payloadStatFunc(func() (os.FileInfo, error) { return base.Stat(".") })
				want = ErrConflict
			case "different-inode":
				if err := os.WriteFile(filepath.Join(p, "different"), []byte("payload"), 0600); err != nil {
					t.Fatal(err)
				}
				name = "different"
				want = ErrConflict
			}
			if err = s.CheckPayload(ctx, name, held); !errors.Is(err, want) {
				t.Fatal(err, want)
			}
		})
	}
}

func TestCarrierPublishPreflight(t *testing.T) {
	failure := errors.New("publication preflight failure")
	for _, scenario := range []string{"cancelled", "closed", "wrong-generation", "overflow", "missing-generation", "invalid-manifest", "stale-generation", "corrupt-manifest", "missing-blob", "locked", "manifest-limit", "temporary-open", "temporary-closed", "cancel-after-prepare"} {
		t.Run(scenario, func(t *testing.T) {
			s, p, m := fixture(t)
			r := fileRecord(t, p)
			manifest := Manifest{Version: 1, Records: []Record{r}}
			expected := uint64(0)
			ctx := t.Context()
			want := ErrConflict
			metadata := s.metadata
			switch scenario {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "closed":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				want = os.ErrClosed
			case "wrong-generation":
				manifest.Generation = 1
			case "overflow":
				manifest.Generation = ^uint64(0)
				expected = manifest.Generation
			case "missing-generation":
				manifest.Generation = 1
				expected = 1
			case "invalid-manifest":
				manifest.Version = 99
				want = ErrInvalid
			case "stale-generation":
				if err := s.Commit(ctx, manifest, 0); err != nil {
					t.Fatal(err)
				}
			case "corrupt-manifest":
				if err := os.WriteFile(filepath.Join(m, "manifest.json"), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
				want = ErrInvalid
			case "missing-blob":
				r.Attributes = []Attribute{{Name: "foreign.attribute", Value: digest([]byte("absent"))}}
				manifest.Records = []Record{r}
				want = ErrCorrupt
			case "locked":
				if err := os.WriteFile(filepath.Join(m, ".lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest-limit":
				s.limits.ManifestBytes = 1
				want = ErrLimit
			case "temporary-open":
				want = failure
				s.metadata = faultRoot{carrierRoot: metadata, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
					if strings.HasPrefix(n, ".manifest-") {
						return nil, failure
					}
					return metadata.OpenFile(n, flags, mode)
				}}
			case "temporary-closed":
				want = os.ErrClosed
				s.metadata = faultRoot{carrierRoot: metadata, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
					f, e := metadata.OpenFile(n, flags, mode)
					if e == nil && strings.HasPrefix(n, ".manifest-") {
						e = f.Close()
					}
					return f, e
				}}
			case "cancel-after-prepare":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				want = context.Canceled
				s.metadata = faultRoot{carrierRoot: metadata, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
					f, e := metadata.OpenFile(n, flags, mode)
					if strings.HasPrefix(n, ".manifest-") {
						cancel()
					}
					return f, e
				}}
			}
			called := false
			published, err := s.Publish(ctx, manifest, expected, func() error { called = true; return nil })
			if published || called || !errors.Is(err, want) {
				t.Fatal("preflight", published, called, err, want)
			}
			data, err := os.ReadFile(filepath.Join(p, r.Materialized))
			if err != nil || digest(data) != *r.Payload {
				t.Fatal("preflight touched payload", err)
			}
			entries, err := os.ReadDir(m)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".manifest-") || entry.Name() == ".lock" && scenario != "locked" {
					t.Fatal("publication staging leaked", entry.Name())
				}
			}
		})
	}
}

func TestCarrierPublishReentrantReadsAndBorrowReuse(t *testing.T) {
	s, p, _ := fixture(t)
	r := fileRecord(t, p)
	attribute := bytes.Repeat([]byte("retained metadata"), 10000)
	ref := mustBlob(t, s, attribute)
	r.Attributes = []Attribute{{Name: "attribute", Value: ref}}
	manifest := Manifest{Version: 1, Records: []Record{r}}
	if err := s.Commit(t.Context(), manifest, 0); err != nil {
		t.Fatal(err)
	}
	borrowed, err := s.BorrowRecordAttributes(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	held, err := s.OpenPayload(t.Context(), r.Materialized)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	for generation := uint64(1); generation < 4; generation++ {
		manifest.Generation = generation
		calls := 0
		published, err := s.Publish(t.Context(), manifest, generation, func() error {
			calls++
			// Fail clearly instead of hanging the suite if callbacks regain the read mutex.
			if !s.mu.TryLock() {
				return errors.New("publication holds the read mutex during callback")
			}
			s.mu.Unlock()
			loaded, e := s.Load(t.Context())
			if e != nil {
				return e
			}
			if loaded.Generation != generation {
				return errors.New("new manifest visible before payload transition")
			}
			if e = s.CheckPayload(t.Context(), r.Materialized, held); e != nil {
				return e
			}
			opened, e := s.OpenBlob(t.Context(), ref)
			if e != nil {
				return e
			}
			body, e := io.ReadAll(opened)
			e = errors.Join(e, opened.Close())
			if e != nil {
				return e
			}
			if !bytes.Equal(body, attribute) {
				return errors.New("blob changed")
			}
			for repeat := 0; repeat < 2; repeat++ {
				body = make([]byte, len(attribute))
				n, e := borrowed["attribute"].ReadAt(body, 0)
				if n != len(body) || e != nil {
					return errors.Join(errors.New("borrowed value read failed"), e)
				}
				if !bytes.Equal(body, attribute) {
					return errors.New("borrowed value changed")
				}
			}
			return s.VerifyPayload(t.Context(), r)
		})
		if err != nil || !published || calls != 1 {
			t.Fatal(published, calls, err)
		}
		got, err := s.Load(t.Context())
		if err != nil || got.Generation != generation+1 {
			t.Fatal(got, err)
		}
	}
}

func TestCarrierPublishMutationAndCleanupOutcomes(t *testing.T) {
	failure := errors.New("publication boundary failure")
	for _, scenario := range []string{"success", "nil-transition", "callback-failure", "callback-cancel", "handled-cancel", "rename-failure", "lock-remove-failure", "lock-close-failure", "temporary-remove-failure"} {
		t.Run(scenario, func(t *testing.T) {
			s, p, m := fixture(t)
			r := fileRecord(t, p)
			metadata := s.metadata
			manifest := Manifest{Version: 1, Records: []Record{r}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "rename-failure" {
				s.metadata = faultRoot{carrierRoot: metadata, rename: func(string, string) error { return failure }}
			}
			if scenario == "lock-remove-failure" || scenario == "temporary-remove-failure" {
				s.metadata = payloadCleanupRoot{carrierRoot: metadata, remove: func(n string) error {
					e := metadata.Remove(n)
					if scenario == "lock-remove-failure" && n == ".lock" || scenario == "temporary-remove-failure" && strings.HasPrefix(n, ".manifest-") {
						return failure
					}
					return e
				}}
			}
			if scenario == "lock-close-failure" {
				s.metadata = faultRoot{carrierRoot: metadata, openFile: func(n string, flags int, mode os.FileMode) (*os.File, error) {
					f, e := metadata.OpenFile(n, flags, mode)
					if e == nil && n == ".lock" {
						e = f.Close()
					}
					return f, e
				}}
			}
			held, err := s.OpenPayload(ctx, r.Materialized)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			called := 0
			transition := func() error {
				called++
				if _, e := held.WriteAt([]byte("changed"), 0); e != nil {
					return e
				}
				if scenario == "callback-failure" {
					return failure
				}
				if scenario == "callback-cancel" || scenario == "handled-cancel" {
					cancel()
					if scenario == "callback-cancel" {
						return ctx.Err()
					}
				}
				return nil
			}
			if scenario == "nil-transition" {
				transition = nil
			}
			published, err := s.Publish(ctx, manifest, 0, transition)
			wantPublished := scenario != "callback-failure" && scenario != "callback-cancel" && scenario != "rename-failure"
			var want error
			switch scenario {
			case "callback-failure", "rename-failure", "lock-remove-failure", "temporary-remove-failure":
				want = failure
			case "callback-cancel":
				want = context.Canceled
			case "lock-close-failure":
				want = os.ErrClosed
			}
			if published != wantPublished || !errors.Is(err, want) {
				t.Fatal("publication outcome", published, err, wantPublished, want)
			}
			wantCalls := 1
			if scenario == "nil-transition" {
				wantCalls = 0
			}
			if called != wantCalls {
				t.Fatal("callback invocations", called)
			}
			data, e := os.ReadFile(filepath.Join(p, r.Materialized))
			if e != nil {
				t.Fatal(e)
			}
			wantData := "changed"
			if scenario == "nil-transition" {
				wantData = "payload"
			}
			if string(data) != wantData {
				t.Fatal("partial effects rolled back or lost", string(data))
			}
			onDisk, e := os.ReadFile(filepath.Join(m, "manifest.json"))
			if wantPublished {
				var got Manifest
				if e != nil {
					t.Fatal(e)
				}
				if e = json.Unmarshal(onDisk, &got); e != nil || got.Generation != 1 {
					t.Fatal(got, e)
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				t.Fatal("failed transition published manifest", e)
			}
		})
	}
}

func TestCarrierPublishSerializesClose(t *testing.T) {
	s, p, m := fixture(t)
	r := fileRecord(t, p)
	held, err := s.OpenPayload(t.Context(), r.Materialized)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	publication := make(chan error, 1)
	closed := make(chan error, 1)
	go func() {
		published, err := s.Publish(t.Context(), Manifest{Version: 1, Records: []Record{r}}, 0, func() error { close(entered); <-release; return s.CheckPayload(t.Context(), r.Materialized, held) })
		if !published {
			err = errors.Join(err, errors.New("publication did not finish"))
		}
		publication <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("transition did not start")
	}
	closeStarted := make(chan struct{})
	go func() { close(closeStarted); closed <- s.Close() }()
	<-closeStarted
	// The callback is active, so Close must wait and read methods remain usable.
	select {
	case err := <-closed:
		close(release)
		t.Fatal("Close invalidated active publication", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err = s.CheckPayload(t.Context(), r.Materialized, held); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-publication:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication blocked on Close")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after publication")
	}
	if _, err = held.Stat(); err != nil {
		t.Fatal("caller-owned payload closed", err)
	}
	body, err := os.ReadFile(filepath.Join(m, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got Manifest
	if err = json.Unmarshal(body, &got); err != nil || got.Generation != 1 {
		t.Fatal(got, err)
	}
}

type payloadReadFunc func([]byte, int64) (int, error)

func (f payloadReadFunc) ReadAt(p []byte, off int64) (int, error) { return f(p, off) }

type payloadWriteFunc func([]byte) (int, error)

func (f payloadWriteFunc) Write(p []byte) (int, error) { return f(p) }

type payloadHeldReader struct {
	io.ReaderAt
	payloadStatFunc
}

func TestCarrierPayloadBoundedIO(t *testing.T) {
	data := bytes.Repeat([]byte("bounded-payload-data"), 10000)
	name := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var reads int
	source := payloadHeldReader{ReaderAt: payloadReadFunc(func(p []byte, off int64) (int, error) {
		reads++
		if len(p) > 64<<10 || off != int64((reads-1)*(64<<10)) {
			t.Fatalf("unbounded or nonsequential read: length=%d offset=%d", len(p), off)
		}
		return file.ReadAt(p, off)
	}), payloadStatFunc: file.Stat}
	ref, err := PayloadReference(t.Context(), source)
	if err != nil || ref != digest(data) || reads < 2 {
		t.Fatal(ref, reads, err)
	}
	reads = 0
	if err := VerifyHeldPayload(t.Context(), source, ref); err != nil {
		t.Fatal(err)
	}
	reads = 0
	var destination bytes.Buffer
	destination.WriteString("prefix")
	if err := CopyPayload(t.Context(), &destination, source, int64(len(data)-3)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(destination.Bytes(), append([]byte("prefix"), data[:len(data)-3]...)) {
		t.Fatal("copy ignored length or destination position")
	}
	// Fingerprinting uses ReaderAt, leaving the caller's descriptor position intact.
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil || position != 0 {
		t.Fatal(position, err)
	}
}

func TestCarrierPayloadReferenceAndVerificationFailures(t *testing.T) {
	failure := errors.New("held payload fault")
	for _, scenario := range []string{"empty", "stat", "read", "short", "cancelled", "wrong-size", "wrong-digest"} {
		t.Run(scenario, func(t *testing.T) {
			data := []byte("payload")
			if scenario == "empty" {
				data = nil
			}
			name := filepath.Join(t.TempDir(), "payload")
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			source := payloadHeldReader{ReaderAt: bytes.NewReader(data), payloadStatFunc: func() (os.FileInfo, error) { return info, nil }}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var want error
			ref := digest(data)
			switch scenario {
			case "stat":
				source.payloadStatFunc = func() (os.FileInfo, error) { return nil, failure }
				want = failure
			case "read":
				source.ReaderAt = payloadReadFunc(func(p []byte, _ int64) (int, error) { return len(p), failure })
				want = failure
			case "short":
				source.ReaderAt = bytes.NewReader(data[:2])
				want = io.ErrUnexpectedEOF
			case "cancelled":
				cancel()
				want = context.Canceled
			case "wrong-size":
				ref.Size++
			case "wrong-digest":
				ref.SHA256 = strings.Repeat("0", 64)
			}
			got, err := PayloadReference(ctx, source)
			if !errors.Is(err, want) {
				t.Fatal("reference", got, err, "want", want)
			}
			if err == nil && got != digest(data) {
				t.Fatal("wrong reference", got)
			}
			if scenario == "wrong-size" || scenario == "wrong-digest" {
				want = ErrCorrupt
			}
			if err := VerifyHeldPayload(ctx, source, ref); !errors.Is(err, want) {
				t.Fatal("verify", err, "want", want)
			}
		})
	}
}

func TestCarrierPayloadCopyFailuresAndCancellation(t *testing.T) {
	failure := errors.New("payload I/O fault")
	for _, scenario := range []string{"negative", "nil-source", "empty", "cancelled", "empty-cancelled", "short-read", "read-failure", "full-eof", "write-failure", "short-write", "cancel-after-block", "cancel-after-final"} {
		t.Run(scenario, func(t *testing.T) {
			data := bytes.Repeat([]byte("p"), 64<<10+1)
			size := int64(len(data))
			var source io.ReaderAt = bytes.NewReader(data)
			var destination bytes.Buffer
			var writer io.Writer = &destination
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var want error
			switch scenario {
			case "negative":
				size, want = -1, ErrInvalid
			case "nil-source":
				source, want = nil, ErrInvalid
			case "empty":
				size = 0
			case "cancelled", "empty-cancelled":
				cancel()
				want = context.Canceled
				if scenario == "empty-cancelled" {
					size = 0
				}
			case "short-read":
				source, want = bytes.NewReader(data[:4]), io.ErrUnexpectedEOF
			case "read-failure":
				source = payloadReadFunc(func(p []byte, _ int64) (int, error) { return len(p), failure })
				want = failure
			case "full-eof":
				source = payloadReadFunc(func(p []byte, off int64) (int, error) { return copy(p, data[off:]), io.EOF })
			case "write-failure":
				writer = payloadWriteFunc(func(p []byte) (int, error) { _, _ = destination.Write(p[:3]); return 3, failure })
				want = failure
			case "short-write":
				writer = payloadWriteFunc(func(p []byte) (int, error) { return destination.Write(p[:3]) })
				want = io.ErrShortWrite
			case "cancel-after-block", "cancel-after-final":
				if scenario == "cancel-after-final" {
					size = 3
				}
				writer = payloadWriteFunc(func(p []byte) (int, error) { n, e := destination.Write(p); cancel(); return n, e })
				want = context.Canceled
			}
			if err := CopyPayload(ctx, writer, source, size); !errors.Is(err, want) {
				t.Fatal(err, "want", want)
			}
			switch scenario {
			case "write-failure", "short-write", "cancel-after-final":
				if destination.Len() != 3 {
					t.Fatal("partial output lost", destination.Len())
				}
			case "cancel-after-block":
				if destination.Len() != 64<<10 {
					t.Fatal("cancellation checkpoint missed", destination.Len())
				}
			case "full-eof":
				if !bytes.Equal(destination.Bytes(), data) {
					t.Fatal("full read with EOF not copied")
				}
			default:
				if destination.Len() != 0 {
					t.Fatal("unexpected output", destination.Len())
				}
			}
		})
	}
}
