package hostdata

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// Controlled backend selection tests the portable implementation on every CI
// host. Real volume selection remains covered by filesystem and codesign CI.
func replacementTestFilesystemView(ctx context.Context, file *os.File) (*FilesystemMetadata, error) {
	return filesystemMetadataForFile(ctx, file, func(*os.File) (bool, error) { return true, nil })
}

func TestReplacementFilesystemNativeCorpus(t *testing.T) {
	profile := osversion.MacOS27
	if raw := os.Getenv("APFS_REPLACEMENT_FILESYSTEM_PROFILE"); raw != "" {
		version, err := osversion.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		profile, err = osversion.ProfileForMacOS(version)
		if err != nil {
			t.Fatal(err)
		}
	}
	path := os.Getenv("APFS_REPLACEMENT_FILESYSTEM_CORPUS")
	if path == "" {
		path = "../../testdata/appledouble/native/replacement-filesystem-macos27/cases.json.gz"
	}
	file, err := os.Open(path)

	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var cases []struct {
		Filesystem, Profile string
		Input, Native       []byte
		Errno               int
	}
	if err = json.NewDecoder(z).Decode(&cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 220 {
		t.Fatal("incomplete native replacement corpus", len(cases))
	}
	successes, failures := 0, 0
	for _, c := range cases {
		t.Run(c.Filesystem+"/"+c.Profile, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			input, err := root.OpenFile("input", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err = input.Write([]byte("original")); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "._input"), c.Input, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := PrepareReplacementAtContext(t.Context(), input, root, ".")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if e := r.Close(); e != nil {
					t.Error(e)
				}
			}()
			state, err := prepareReplacementFilesystemUsingForProfile(t.Context(), input, r.File, replacementTestFilesystemView, profile)
			r.filesystem = state
			if c.Errno != 0 {
				failures++
				if c.Errno != 22 || !errors.Is(err, syscall.EINVAL) {
					t.Fatalf("copy error=%v native errno=%d", err, c.Errno)
				}
				original, e := os.ReadFile(filepath.Join(dir, "._input"))
				if e != nil || !bytes.Equal(original, c.Input) {
					t.Fatal("failed preparation changed source", e)
				}
				if e = r.Close(); e != nil {
					t.Fatal(e)
				}
				if _, e = root.Lstat(filepath.Dir(r.Path)); !os.IsNotExist(e) {
					t.Fatal("failed preparation retained stage", e)
				}
				return
			}
			successes++
			if err != nil {
				t.Fatal(err)
			}
			stageCarrier := filepath.Join(dir, filepath.Dir(r.Path), "._replacement")
			encoded, err := os.ReadFile(stageCarrier)
			if err != nil || !bytes.Equal(encoded, c.Native) {
				t.Fatalf("staged native bytes differ: %v", err)
			}
			if _, err = r.File.Write([]byte("replacement")); err != nil {
				t.Fatal(err)
			}
			if err = r.File.Truncate(11); err != nil {
				t.Fatal(err)
			}
			if err = r.File.Close(); err != nil {
				t.Fatal(err)
			}
			if err = input.Close(); err != nil {
				t.Fatal(err)
			}
			if err = r.PublishContext(t.Context(), "input"); err != nil {
				t.Fatal(err)
			}
			if err = r.PublishContext(t.Context(), "input"); !errors.Is(err, os.ErrInvalid) {
				t.Fatal("duplicate publication", err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "input"))
			if err != nil || string(data) != "replacement" {
				t.Fatal(string(data), err)
			}
			metadata, err := os.ReadFile(filepath.Join(dir, "._input"))
			if err != nil || !bytes.Equal(metadata, c.Native) {
				t.Fatal("published native metadata differs", err)
			}
			if err = r.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = root.Lstat(filepath.Dir(r.Path)); !os.IsNotExist(err) {
				t.Fatal("published stage retained", err)
			}
		})
	}
	expectedFailures := 100
	if profile == osversion.MacOS15 {
		expectedFailures = 0
	}
	if successes != 220-expectedFailures || failures != expectedFailures {
		t.Fatal("native case membership changed", successes, failures)
	}
}

func TestReplacementFilesystemPreparationFailures(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.CreateTemp(t.TempDir(), "target")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	sentinel := io.ErrClosedPipe
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = prepareReplacementFilesystemUsing(canceled, source, target, replacementTestFilesystemView); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, which := range []int{1, 2} {
		calls := 0
		open := func(ctx context.Context, f *os.File) (*FilesystemMetadata, error) {
			calls++
			if calls == which {
				return nil, sentinel
			}
			return replacementTestFilesystemView(ctx, f)
		}
		if _, err = prepareReplacementFilesystemUsing(t.Context(), source, target, open); !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
	}
	open := func(ctx context.Context, f *os.File) (*FilesystemMetadata, error) {
		return filesystemMetadataForFile(ctx, f, func(*os.File) (bool, error) { return false, nil })
	}
	if _, err = prepareReplacementFilesystemUsing(t.Context(), source, target, open); !errors.Is(err, ErrUnsupportedReplacement) {
		t.Fatal(err)
	}
	state, err := prepareReplacementFilesystemUsing(t.Context(), source, target, replacementTestFilesystemView)
	if err != nil || state == nil || state.sourceCarrier != nil || state.stagedCarrier != nil {
		t.Fatal(state, err)
	}
	if err = os.WriteFile(filepath.Join(filepath.Dir(source.Name()), "._"+filepath.Base(source.Name())), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareReplacementFilesystemUsing(t.Context(), source, target, replacementTestFilesystemView); err == nil {
		t.Fatal("invalid source carrier accepted")
	}
}

func TestReplacementFilesystemPublicationFailures(t *testing.T) {
	for _, scenario := range []string{"success", "empty", "remove", "cancel-before", "cancel-after-check", "cancel-after-data", "published", "escape-source", "escape-target", "stat-error", "wrong-source", "unexpected-carrier", "missing-stage", "rename-data", "rename-carrier", "remove-carrier"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			state := &replacementFilesystem{}
			for name, dest := range map[string]*os.FileInfo{"source": &state.source, "stage": &state.staged, "._source": &state.sourceCarrier, "._stage": &state.stagedCarrier} {
				if err = os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
					t.Fatal(err)
				}
				*dest, err = root.Stat(name)
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ops := replacementPublicationOps{stat: root.Stat, rename: root.Rename, remove: root.Remove}
			from, to := "stage", "source"
			var want error
			partial := false
			switch scenario {
			case "empty", "remove":
				if err = root.Remove("._stage"); err != nil {
					t.Fatal(err)
				}
				state.stagedCarrier = nil
				if scenario == "empty" {
					if err = root.Remove("._source"); err != nil {
						t.Fatal(err)
					}
					state.sourceCarrier = nil
				}
			case "cancel-before":
				cancel()
				want = context.Canceled
			case "cancel-after-check":
				ops.stat = func(name string) (os.FileInfo, error) {
					if name == "._source" {
						cancel()
					}
					return root.Stat(name)
				}
				want = context.Canceled
			case "cancel-after-data":
				ops.rename = func(a, b string) error {
					e := root.Rename(a, b)
					if a == from {
						cancel()
					}
					return e
				}
				want = context.Canceled
			case "published":
				state.published = true
				want = os.ErrInvalid
			case "escape-source":
				from = "../stage"
				want = os.ErrInvalid
			case "escape-target":
				to = "../source"
				want = os.ErrInvalid
			case "stat-error":
				ops.stat = func(string) (os.FileInfo, error) { return nil, io.ErrClosedPipe }
				want = io.ErrClosedPipe
			case "wrong-source":
				state.source = state.staged
				want = ErrMetadataIdentity
			case "unexpected-carrier":
				state.sourceCarrier = nil
				want = ErrMetadataIdentity
			case "missing-stage":
				if err = root.Remove("stage"); err != nil {
					t.Fatal(err)
				}
				want = os.ErrNotExist
			case "rename-data":
				ops.rename = func(string, string) error { return io.ErrClosedPipe }
				want = io.ErrClosedPipe
			case "rename-carrier":
				ops.rename = func(a, b string) error {
					if a == "._stage" {
						return io.ErrClosedPipe
					}
					return root.Rename(a, b)
				}
				want = io.ErrClosedPipe
				partial = true
			case "remove-carrier":
				if err = root.Remove("._stage"); err != nil {
					t.Fatal(err)
				}
				state.stagedCarrier = nil
				ops.remove = func(string) error { return io.ErrClosedPipe }
				want = io.ErrClosedPipe
				partial = true
			}
			err = publishFilesystemReplacementUsing(ctx, from, to, state, ops)
			if !errors.Is(err, want) {
				t.Fatalf("error %v want %v", err, want)
			}
			var publication *ReplacementPublicationError
			if errors.As(err, &publication) != partial {
				t.Fatalf("partial publication classification: %v", err)
			}
			if partial && publication.Error() != "replacement data published; metadata publication failed: io: read/write on closed pipe" {
				t.Fatal(publication.Error())
			}
			published := want == nil || partial || scenario == "cancel-after-data"
			data, e := os.ReadFile(filepath.Join(dir, "source"))
			if e != nil {
				t.Fatal(e)
			}
			if published && string(data) != "stage" || !published && string(data) != "source" {
				t.Fatalf("destination data after %s: %s", scenario, data)
			}
			if scenario == "cancel-after-data" || scenario == "success" {
				data, e = os.ReadFile(filepath.Join(dir, "._source"))
				if e != nil || string(data) != "._stage" {
					t.Fatal("metadata publication was interrupted", string(data), e)
				}
			}
			if scenario == "empty" || scenario == "remove" {
				if _, e = root.Stat("._source"); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("old carrier remains", e)
				}
			}
		})
	}
}

func TestReplacementFilesystemPublicationAPIs(t *testing.T) {
	for _, api := range []string{"path", "root"} {
		for _, foreign := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/foreign-%t", api, foreign), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "source")
				source, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if api == "path" {
					r, e := PrepareReplacementContext(t.Context(), source, dir)
					if e != nil {
						t.Fatal(e)
					}
					defer r.Close()
					if foreign {
						r.filesystem, e = prepareReplacementFilesystemUsing(t.Context(), source, r.File, replacementTestFilesystemView)
						if e != nil {
							t.Fatal(e)
						}
					}
					if e = r.PublishContext(ctx, path); !errors.Is(e, context.Canceled) {
						t.Fatal(e)
					}
					if foreign {
						if e = r.PublishContext(t.Context(), filepath.Join(t.TempDir(), "other")); !errors.Is(e, os.ErrInvalid) {
							t.Fatal(e)
						}
					}
					if e = r.RestoreMetadataContext(t.Context()); e != nil {
						t.Fatal(e)
					}
					if e = r.File.Close(); e != nil {
						t.Fatal(e)
					}
					if e = source.Close(); e != nil {
						t.Fatal(e)
					}
					if e = r.PublishContext(t.Context(), path); e != nil {
						t.Fatal(e)
					}
				} else {
					root, e := os.OpenRoot(dir)
					if e != nil {
						t.Fatal(e)
					}
					defer root.Close()
					r, e := PrepareReplacementAtContext(t.Context(), source, root, ".")
					if e != nil {
						t.Fatal(e)
					}
					defer r.Close()
					if foreign {
						r.filesystem, e = prepareReplacementFilesystemUsing(t.Context(), source, r.File, replacementTestFilesystemView)
						if e != nil {
							t.Fatal(e)
						}
					}
					if e = r.PublishContext(ctx, "source"); !errors.Is(e, context.Canceled) {
						t.Fatal(e)
					}
					if e = r.RestoreMetadataContext(t.Context()); e != nil {
						t.Fatal(e)
					}
					if e = r.File.Close(); e != nil {
						t.Fatal(e)
					}
					if e = source.Close(); e != nil {
						t.Fatal(e)
					}
					if e = r.PublishContext(t.Context(), "source"); e != nil {
						t.Fatal(e)
					}
					if e = r.Close(); e != nil {
						t.Fatal(e)
					}
					if e = r.PublishContext(t.Context(), "source"); !errors.Is(e, os.ErrClosed) {
						t.Fatal(e)
					}
				}
			})
		}
	}
}

type replacementFilesystemFaultWriter struct {
	*os.File
	operation string
}

func (f replacementFilesystemFaultWriter) Write(p []byte) (int, error) {
	if f.operation == "write" {
		return 0, io.ErrClosedPipe
	}
	return f.File.Write(p)
}
func (f replacementFilesystemFaultWriter) Sync() error {
	if f.operation == "sync" {
		return io.ErrClosedPipe
	}
	return f.File.Sync()
}
func (f replacementFilesystemFaultWriter) Stat() (os.FileInfo, error) {
	if f.operation == "stat" {
		return nil, io.ErrClosedPipe
	}
	return f.File.Stat()
}
func (f replacementFilesystemFaultWriter) Close() error {
	e := f.File.Close()
	if f.operation == "close" {
		return errors.Join(e, io.ErrClosedPipe)
	}
	return e
}

func TestReplacementFilesystemStageFailures(t *testing.T) {
	for _, operation := range []string{"create", "write", "sync", "stat", "close", "cancel-checkpoints"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			source, e := os.Create(filepath.Join(dir, "source"))
			if e != nil {
				t.Fatal(e)
			}
			defer source.Close()
			target, e := os.Create(filepath.Join(dir, "target"))
			if e != nil {
				t.Fatal(e)
			}
			defer target.Close()
			metadata := &appledouble.StreamFile{FinderInfo: [32]byte{1}, Attrs: []appledouble.StreamAttr{{Name: "com.example.test", Value: bytes.NewReader([]byte("retained"))}}}
			var packed bytes.Buffer
			if _, e = metadata.EncodeTo(t.Context(), &packed, appledouble.DefaultStreamLimits()); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, "._source"), packed.Bytes(), 0600); e != nil {
				t.Fatal(e)
			}
			create := func(view *FilesystemMetadata) (replacementFilesystemWriter, error) {
				if operation == "create" {
					return nil, io.ErrClosedPipe
				}
				f, e := view.parent.OpenFile("._"+view.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					return nil, e
				}
				return replacementFilesystemFaultWriter{f, operation}, nil
			}
			if operation != "cancel-checkpoints" {
				state, e := prepareReplacementFilesystemWith(t.Context(), source, target, replacementTestFilesystemView, create)
				if !errors.Is(e, io.ErrClosedPipe) {
					t.Fatal(e)
				}
				if operation != "create" && state == nil {
					t.Fatal("lost partial stage cleanup state")
				}
				unchanged, e := os.ReadFile(filepath.Join(dir, "._source"))
				if e != nil || !bytes.Equal(unchanged, packed.Bytes()) {
					t.Fatal("source mutated", e)
				}
				return
			}
			base, cancel := context.WithCancel(t.Context())
			ctx := &replacementCheckpointContext{Context: base, cancel: cancel}
			if _, e = prepareReplacementFilesystemWith(ctx, source, target, replacementTestFilesystemView, create); e != nil {
				t.Fatal(e)
			}
			cancel()
			calls := ctx.calls
			if e = os.Remove(filepath.Join(dir, "._target")); e != nil {
				t.Fatal(e)
			}
			for stop := 1; stop <= calls; stop++ {
				base, cancel = context.WithCancel(t.Context())
				ctx = &replacementCheckpointContext{Context: base, cancel: cancel, stop: stop}
				_, e = prepareReplacementFilesystemWith(ctx, source, target, replacementTestFilesystemView, create)
				cancel()
				if !errors.Is(e, context.Canceled) {
					t.Fatalf("checkpoint %d: %v", stop, e)
				}
				if e = os.Remove(filepath.Join(dir, "._target")); e != nil && !errors.Is(e, os.ErrNotExist) {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestReplacementFilesystemMissingPublicationParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	if e := os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	stage := filepath.Join(parent, "stage")
	if e := os.Mkdir(stage, 0700); e != nil {
		t.Fatal(e)
	}
	file, e := os.Create(filepath.Join(stage, "replacement"))
	if e != nil {
		t.Fatal(e)
	}
	if e = file.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(parent); e != nil {
		t.Fatal(e)
	}
	replacement := &Replacement{File: file, filesystem: &replacementFilesystem{}}
	if e = replacement.PublishContext(t.Context(), filepath.Join(parent, "source")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}
