package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementContextCancellation(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err = source.WriteString("original"); err != nil {
		t.Fatal(err)
	}
	for _, rooted := range []bool{false, true} {
		t.Run(map[bool]string{false: "path", true: "root"}[rooted], func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if rooted {
				r, e := PrepareReplacementAtContext(ctx, source, root, ".")
				if r != nil || !errors.Is(e, context.Canceled) {
					t.Fatal(r, e)
				}
			} else {
				r, e := PrepareReplacementContext(ctx, source, dir)
				if r != nil || !errors.Is(e, context.Canceled) {
					t.Fatal(r, e)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal(entries, err)
			}
			if rooted {
				r, e := PrepareReplacementAtContext(t.Context(), source, root, ".")
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				if e = r.RestoreMetadataContext(ctx); !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				if e = r.RestoreMetadataContext(t.Context()); e != nil {
					t.Fatal(e)
				}
			} else {
				r, e := PrepareReplacementContext(t.Context(), source, dir)
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				if e = r.RestoreMetadataContext(ctx); !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				if e = r.RestoreMetadataContext(t.Context()); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
	if b, err := os.ReadFile(source.Name()); err != nil || string(b) != "original" {
		t.Fatal(string(b), err)
	}
}
func TestReplacementCleanupErrors(t *testing.T) {
	first, second := errors.New("permission cleanup"), errors.New("remove cleanup")
	calls := 0
	err := cleanupReplacement(func() error { calls++; return first }, func() error { calls++; return &os.PathError{Op: "remove", Path: "private", Err: os.ErrNotExist} }, func() error { calls++; return second })
	if calls != 3 || !errors.Is(err, first) || !errors.Is(err, second) || errors.Is(err, os.ErrNotExist) {
		t.Fatal(calls, err)
	}
}
func TestReplacementContextSteps(t *testing.T) {
	fault := errors.New("native call failed")
	ctx, cancel := context.WithCancel(t.Context())
	if err := replacementStep(ctx, func() error { cancel(); return fault }); !errors.Is(err, fault) || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	called := false
	if err := replacementStep(ctx, func() error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal(called, err)
	}
	if _, err := replacementValue(ctx, func() (int, error) { called = true; return 3, nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal(called, err)
	}
	for _, stop := range []string{"preflight", "clone", "open", "metadata"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if stop == "preflight" {
				cancel()
			}
			var held *os.File
			cloneCalls := 0
			f, err := prepareReplacementUsingContext(ctx, func() error {
				cloneCalls++
				if stop == "clone" {
					cancel()
				}
				return errors.ErrUnsupported
			}, func(e error) bool { return errors.Is(e, errors.ErrUnsupported) }, func(bool) (*os.File, error) {
				var e error
				held, e = os.Create(filepath.Join(t.TempDir(), "stage"))
				if stop == "open" {
					cancel()
				}
				return held, e
			}, func(*os.File) error {
				if stop == "metadata" {
					cancel()
				}
				return nil
			})
			if f != nil || !errors.Is(err, context.Canceled) {
				t.Fatal(f, err)
			}
			if stop == "preflight" && cloneCalls != 0 {
				t.Fatal("clone after cancellation")
			}
			if held != nil {
				if n, e := held.Write([]byte("closed-capability-probe")); n != 0 || !errors.Is(e, os.ErrClosed) {
					t.Fatal("staging handle leaked", e)
				}
			}
		})
	}
}
func TestReplacementBackupBeyondLegacyLimits(t *testing.T) {
	for _, input := range [][]byte{
		append(backupRecord(4, 8, ":large-sparse:$DATA", nil), backupExtent(1<<34, "x")...),
		backupRecord(4, 0, ":large:$DATA", bytes.Repeat([]byte{0xa5}, (8<<20)+1)),
		backupRecord(2, 0, "", bytes.Repeat([]byte{0x37}, (8<<20)+1)),
		bytes.Repeat(backupRecord(4, 0, ":many:$DATA", nil), 65537),
	} {
		var output bytes.Buffer
		if err := filterReplacementStreamsContext(t.Context(), bytes.NewReader(input), &output); err != nil || !bytes.Equal(input, output.Bytes()) {
			t.Fatal("stream limit/byte drift", len(input), err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := filterReplacementStreamsContext(ctx, bytes.NewReader(nil), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// Cancel synchronously at each observable Context checkpoint, including after
// successful native acquisition. The embedded context keeps cancellation sticky.
type replacementCheckpointContext struct {
	context.Context
	cancel      context.CancelFunc
	stop, calls int
}

func (c *replacementCheckpointContext) Err() error {
	c.calls++
	if c.stop != 0 && c.calls == c.stop {
		c.cancel()
	}
	return c.Context.Err()
}

func TestReplacementEveryCancellationCheckpoint(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err = source.WriteString("unchanged source"); err != nil {
		t.Fatal(err)
	}
	for _, rooted := range []bool{false, true} {
		name := map[bool]string{false: "path", true: "root"}[rooted]
		t.Run(name, func(t *testing.T) {
			for _, restore := range []bool{false, true} {
				// First observe a complete operation, then interrupt every checkpoint.
				checkpoints := 0
				for stop := 0; stop <= checkpoints; stop++ {
					dir := t.TempDir()
					root, e := os.OpenRoot(dir)
					if e != nil {
						t.Fatal(e)
					}
					base, cancel := context.WithCancel(t.Context())
					ctx := &replacementCheckpointContext{Context: base, cancel: cancel, stop: stop}
					var closeStage func() error
					var restoreStage func(context.Context) error
					var file *os.File
					preparationCtx := context.Context(ctx)
					if restore {
						preparationCtx = t.Context()
					}
					if rooted {
						r, e := PrepareReplacementAtContext(preparationCtx, source, root, ".")
						err = e
						if r != nil {
							file = r.File
							closeStage = r.Close
							restoreStage = r.RestoreMetadataContext
						}
					} else {
						r, e := PrepareReplacementContext(preparationCtx, source, dir)
						err = e
						if r != nil {
							file = r.File
							closeStage = r.Close
							restoreStage = r.RestoreMetadataContext
						}
					}
					if restore && err == nil {
						err = restoreStage(ctx)
					}
					if stop == 0 {
						if err != nil {
							t.Fatal(err)
						}
						checkpoints = ctx.calls
					} else if !errors.Is(err, context.Canceled) {
						t.Fatalf("restore=%v stop=%d/%d: %v", restore, stop, checkpoints, err)
					}
					cancel()
					if closeStage != nil {
						if e := closeStage(); e != nil {
							t.Fatal(e)
						}
					}
					if file != nil {
						if n, e := file.Write([]byte("closed-capability-probe")); n != 0 || !errors.Is(e, os.ErrClosed) {
							t.Fatalf("stage handle leaked: %v", e)
						}
					}
					if e := root.Close(); e != nil {
						t.Fatal(e)
					}
					entries, e := os.ReadDir(dir)
					if e != nil || len(entries) != 0 {
						t.Fatalf("restore=%v stop=%d stage leaked: %v %v", restore, stop, entries, e)
					}
				}
				if checkpoints == 0 {
					t.Fatal("no cancellation checkpoints")
				}
			}
		})
	}
	if data, e := os.ReadFile(source.Name()); e != nil || string(data) != "unchanged source" {
		t.Fatalf("source changed: %q %v", data, e)
	}
}

func TestReplacementCopyCancellationAndCleanup(t *testing.T) {
	fault, cleanup := errors.New("transfer failure"), errors.New("fork cleanup failure")
	ctx, cancel := context.WithCancel(t.Context())
	value, err := replacementValue(ctx, func() (int, error) { cancel(); return 7, fault })
	if value != 7 || !errors.Is(err, fault) || !errors.Is(err, context.Canceled) {
		t.Fatal(value, err)
	}
	joined := cleanupReplacement(func() error { return errors.Join(os.ErrNotExist, cleanup) })
	if !errors.Is(joined, cleanup) {
		t.Fatalf("joined cleanup failure lost: %v", joined)
	}
	ops := replacementCopyOps{
		list:     func() ([]string, error) { t.Fatal("list after cancel"); return nil, nil },
		read:     func(string, int) ([]byte, bool, error) { t.Fatal("read after cancel"); return nil, false, nil },
		write:    func(string, []byte) error { t.Fatal("write after cancel"); return nil },
		openFork: func() (replacementFork, error) { t.Fatal("open after cancel"); return nil, nil },
		birth:    func() error { t.Fatal("birth after cancel"); return nil },
	}.withContext(ctx)
	if _, err = ops.list(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err = ops.read("attr", 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = ops.write("attr", nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = ops.openFork(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = ops.birth(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = copyReplacementMetadataUsingContext(ctx, ops); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = copyReplacementForkContext(ctx, ops); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, nativeError := range []error{nil, fault} {
		file, e := os.CreateTemp(t.TempDir(), "fork")
		if e != nil {
			t.Fatal(e)
		}
		fork := &replacementTestFork{File: file, closeErr: cleanup}
		active, stop := context.WithCancel(t.Context())
		wrapped := replacementCopyOps{openFork: func() (replacementFork, error) { stop(); return fork, nativeError }}.withContext(active)
		got, e := wrapped.openFork()
		if got != nil || !fork.closed || !errors.Is(e, context.Canceled) || !errors.Is(e, cleanup) || (nativeError != nil && !errors.Is(e, nativeError)) {
			t.Fatal(got, fork.closed, e)
		}
	}
}

func TestReplacementHeldAuxiliaryCleanup(t *testing.T) {
	fault := errors.New("dependent operation")
	for _, which := range []string{"pre-cancel", "open", "late-cancel", "use", "close", "success"} {
		t.Run(which, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if which == "pre-cancel" {
				cancel()
			}
			var auxiliary, result *os.File
			got, e := replacementWithHandle(ctx, func() (*os.File, error) {
				if which == "open" {
					return nil, fault
				}
				var err error
				auxiliary, err = os.CreateTemp(t.TempDir(), "auxiliary")
				if which == "late-cancel" {
					cancel()
				}
				return auxiliary, err
			}, func(held *os.File) (*os.File, error) {
				if held != auxiliary {
					t.Fatal("wrong auxiliary capability")
				}
				if which == "use" {
					return nil, fault
				}
				if which == "close" {
					if e := held.Close(); e != nil {
						t.Fatal(e)
					}
				}
				var err error
				result, err = os.CreateTemp(t.TempDir(), "replacement")
				return result, err
			})
			if which == "success" {
				if e != nil || got != result {
					t.Fatal(got, e)
				}
				if e = got.Close(); e != nil {
					t.Fatal(e)
				}
			} else {
				if e == nil || got != nil {
					t.Fatal(got, e)
				}
			}
			if auxiliary != nil {
				if n, e := auxiliary.Write([]byte("closed-capability-probe")); n != 0 || !errors.Is(e, os.ErrClosed) {
					t.Fatalf("auxiliary leak: %v", e)
				}
			}
			if result != nil {
				if n, e := result.Write([]byte("closed-capability-probe")); n != 0 || !errors.Is(e, os.ErrClosed) {
					t.Fatalf("result leak: %v", e)
				}
			}
		})
	}
	for _, cloned := range []bool{false, true} {
		called := false
		got, e := replacementOpenAfterClone(cloned, func() error { return fault }, func(bool) (*os.File, error) { called = true; return nil, fault })
		if got != nil || !errors.Is(e, fault) || called == cloned {
			t.Fatal(cloned, called, got, e)
		}
	}
}

func TestReplacementHeldIdentityMismatch(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	other, err := os.CreateTemp(t.TempDir(), "other")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherInfo, err := other.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r, err := PrepareReplacement(source, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	setReplacementTestInfo(r, otherInfo)
	if err = r.RestoreMetadataContext(t.Context()); err == nil {
		t.Fatal("accepted mismatched held identity")
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	rooted, err := PrepareReplacementAt(source, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer rooted.Close()
	rooted.info = otherInfo
	if err = rooted.RestoreMetadataContext(t.Context()); err == nil {
		t.Fatal("accepted mismatched rooted identity")
	}
}
