package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

type recompressionInputFuncs struct {
	snapshot  func() (CompressionFileState, error)
	write     func() error
	duplicate func() (CompressionStream, error)
	close     func() error
}

func (b recompressionInputFuncs) Snapshot() (CompressionFileState, error) { return b.snapshot() }
func (b recompressionInputFuncs) ProbeWrite() error                       { return b.write() }
func (b recompressionInputFuncs) Duplicate() (CompressionStream, error)   { return b.duplicate() }
func (b recompressionInputFuncs) Close() error                            { return b.close() }

type recompressionStreamFuncs struct {
	CompressionInstallationBackend
	read   func([]byte, int64) (int, error)
	volume func() (uint32, error)
	close  func() error
}

func (b recompressionStreamFuncs) ReadAt(p []byte, at int64) (int, error) { return b.read(p, at) }
func (b recompressionStreamFuncs) VolumeFlags() (uint32, error)           { return b.volume() }
func (b recompressionStreamFuncs) Close() error                           { return b.close() }

type recompressionStageFile struct {
	*os.File
	close func() error
}

func (b recompressionStageFile) Close() error { return b.close() }

type recompressionHarness struct {
	t                   *testing.T
	dir                 string
	input, stream, fork *os.File
	source              StatCopySource
	logical             *LogicalMetadata
	attribute           []byte
	plain               []byte
	events              []string
	fault, cancelAt     string
	cancel              context.CancelFunc
	sentinel            error
	volume              uint32
	size                int64
	statCalls           int
	open                func(context.Context) (CompressionInput, error)
	options             RecompressionOptions
}

func newRecompressionHarness(t *testing.T, plain []byte) *recompressionHarness {
	t.Helper()
	h := &recompressionHarness{t: t, dir: t.TempDir(), plain: plain, size: int64(len(plain)), sentinel: errors.New("operation fault"), source: StatCopySource{Mode: 0100600, Times: FileTimes{Modify: time.Unix(1600000000, 987654321), Access: time.Unix(1550000000, 345678901)}}}
	var e error
	h.logical, e = NewLogicalMetadata(MetadataState{Stat: h.source, Security: SecurityCopySource{Mode: h.source.Mode}})
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(h.dir, "data")
	if e = os.WriteFile(path, plain, 0600); e != nil {
		t.Fatal(e)
	}
	h.open = func(context.Context) (CompressionInput, error) {
		if e := h.call("open"); e != nil {
			return nil, e
		}
		if h.fault == "nil-input" {
			return nil, nil
		}
		h.input, e = os.OpenFile(path, os.O_RDWR, 0)
		if e != nil {
			return nil, e
		}
		return recompressionInputFuncs{snapshot: func() (CompressionFileState, error) {
			h.statCalls++
			operation := "admission-stat"
			if h.statCalls == 2 {
				operation = "source-stat"
			}
			if e := h.call(operation); e != nil {
				return CompressionFileState{}, e
			}
			source := h.source
			if h.fault == "invalid-mode" && h.statCalls == 2 {
				source.Mode = 65536
			}
			return CompressionFileState{Size: h.size, Stat: source}, nil
		}, write: func() error { return h.call("probe-write") }, duplicate: func() (CompressionStream, error) {
			if e := h.call("duplicate"); e != nil {
				return nil, e
			}
			if h.fault == "nil-stream" {
				return nil, nil
			}
			h.stream, e = os.OpenFile(path, os.O_RDWR, 0)
			if e != nil {
				return nil, e
			}
			commit := compressionCommitFunctions{compressionFlagFunctions: compressionFlagFunctions{read: func() (uint32, error) {
				if e := h.call("flags"); e != nil {
					return 0, e
				}
				return h.logical.ReadFlags()
			}, compare: func(a, b uint32) (uint32, error) {
				if e := h.call("activate"); e != nil {
					return 0, e
				}
				return h.logical.CompareAndSwapFlags(a, b)
			}}, attribute: func(p []byte) error {
				if e := h.call("attribute"); e != nil {
					return e
				}
				h.attribute = bytes.Clone(p)
				return nil
			}, mode: h.logical.Chmod, truncate: func(n int64) error {
				if e := h.call("truncate"); e != nil {
					return e
				}
				return h.stream.Truncate(n)
			}, sync: func() error {
				if e := h.call("data-sync"); e != nil {
					return e
				}
				return h.stream.Sync()
			}, times: func(m, a time.Time) error {
				if e := h.call("times"); e != nil {
					return e
				}
				return h.logical.SetTimes(m, a)
			}}
			install := compressionInstallFunctions{CompressionCommitBackend: commit, open: func() (CompressionForkWriter, error) {
				if e := h.call("open-fork"); e != nil {
					return nil, e
				}
				if h.fault == "nil-fork" {
					return nil, nil
				}
				h.fork, e = os.OpenFile(filepath.Join(h.dir, "fork"), os.O_CREATE|os.O_RDWR, 0600)
				if e != nil {
					return nil, e
				}
				return compressionForkFunctions{write: func(p []byte, at int64) (int, error) {
					if e := h.call("fork-write"); e != nil {
						return 0, e
					}
					return h.fork.WriteAt(p, at)
				}, sync: func() error {
					if e := h.call("fork-sync"); e != nil {
						return e
					}
					return h.fork.Sync()
				}, close: func() error { return errors.Join(h.call("fork-close"), h.fork.Close()) }}, nil
			}, size: func() (int64, error) {
				if e := h.call("fork-size"); e != nil {
					return 0, e
				}
				s, e := h.fork.Stat()
				if e != nil {
					return 0, e
				}
				return s.Size(), nil
			}}
			return recompressionStreamFuncs{CompressionInstallationBackend: install, read: func(p []byte, at int64) (int, error) {
				if e := h.call("read"); e != nil {
					return 0, e
				}
				return h.stream.ReadAt(p, at)
			}, volume: func() (uint32, error) { return h.volume, h.call("volume") }, close: func() error { return errors.Join(h.call("close-stream"), h.stream.Close()) }}, nil
		}, close: func() error { return errors.Join(h.call("close-input"), h.input.Close()) }}, nil
	}
	h.options = RecompressionOptions{Name: "target", NewStage: func(context.Context) (CompressionStage, error) {
		if e := h.call("stage-create"); e != nil {
			return nil, e
		}
		if h.fault == "nil-stage" {
			return nil, nil
		}
		f, e := os.CreateTemp(h.dir, "stage-")
		if e != nil {
			return nil, e
		}
		return recompressionStageFile{File: f, close: func() error { return errors.Join(h.call("stage-close"), f.Close(), os.Remove(f.Name())) }}, nil
	}}
	return h
}
func (h *recompressionHarness) call(name string) error {
	h.events = append(h.events, name)
	if name == h.cancelAt {
		h.cancel()
	}
	if name == h.fault {
		return h.sentinel
	}
	return nil
}
func (h *recompressionHarness) cleanupCheck() {
	h.t.Helper()
	for _, f := range []*os.File{h.input, h.stream, h.fork} {
		if f == nil {
			continue
		}
		var p [1]byte
		if _, e := f.ReadAt(p[:], 0); !errors.Is(e, os.ErrClosed) {
			h.t.Fatal("owned descriptor leaked", f.Name(), e)
		}
	}
	files, e := filepath.Glob(filepath.Join(h.dir, "stage-*"))
	if e != nil || len(files) != 0 {
		h.t.Fatal("private staging leaked", files, e)
	}
	for _, name := range []string{"close-input", "close-stream", "fork-close", "stage-close"} {
		if count := countOperation(h.events, name); count > 1 {
			h.t.Fatal("duplicate cleanup", h.events)
		}
	}
}
func countOperation(events []string, name string) int {
	n := 0
	for _, s := range events {
		if s == name {
			n++
		}
	}
	return n
}

func TestRecompressNativeStorage(t *testing.T) {
	testRecompressNativeStorage(t, compressionLifecycleTrials(t))
}
func TestRecompressNativeOperationProfiles(t *testing.T) {
	for _, name := range []string{"compression-operation", "compression-operation-macos26", "compression-operation-macos15", "allocation-observations/macos27-first", "allocation-observations/macos27-second"} {
		t.Run(name, func(t *testing.T) { testRecompressNativeStorage(t, compressionTrials(t, name, 330)) })
	}
}
func testRecompressNativeStorage(t *testing.T, trials []compressionLifecycleTrial) {
	t.Helper()
	count := 0
	for index, c := range trials {
		if c.Fault != "" || c.Scenario != "ordinary" && c.Scenario != "multi-block" {
			continue
		}
		count++
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			h := newRecompressionHarness(t, c.Data)
			h.volume = c.Observation.VolumeFlags
			switch c.Requested {
			case "3":
				h.options.Encoding.Type = 3
			case "7":
				h.options.Encoding.Type = 7
			case "9":
				h.options.Encoding.Type = 9
			case "11":
				h.options.Encoding.Type = 11
			case "13":
				h.options.Encoding.Type = 13
			}
			h.options.Encoding.ResourceForkOnly = c.Inline == "no"
			r, e := Recompress(t.Context(), h.open, h.options)
			if e != nil || !r.Accepted || r.Declined != "" || !r.Installation.Commit.Activated {
				t.Fatal(r, e, h.events)
			}
			h.cleanupCheck()
			fork, e := os.ReadFile(filepath.Join(h.dir, "fork"))
			if e != nil || !bytes.Equal(fork, c.Fork) || !bytes.Equal(h.attribute, c.Attribute) {
				t.Fatal("complete native storage differs", e)
			}
			data, e := os.ReadFile(filepath.Join(h.dir, "data"))
			if e != nil || len(data) != 0 {
				t.Fatal("ordinary data survived truncation", e)
			}
			got := h.logical.Snapshot().Stat
			if got.Flags != 0x20 || !got.Times.Modify.Equal(h.source.Times.Modify.Truncate(time.Microsecond)) || !got.Times.Access.Equal(h.source.Times.Access.Truncate(time.Microsecond)) {
				t.Fatal("restoration", got)
			}
			if slices.Index(h.events, "open-fork") > slices.Index(h.events, "read") || slices.Index(h.events, "fork-close") > slices.Index(h.events, "attribute") {
				t.Fatal("native acquisition/install order", h.events)
			}
		})
	}
	if count != 66 {
		t.Fatal("native inventory", count)
	}
}

func TestRecompressAdmissionAndDeclines(t *testing.T) {
	for _, size := range []int64{-1, 0, 16383, 16384, 512<<20 + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			h := newRecompressionHarness(t, nil)
			h.size = size
			r, e := Recompress(t.Context(), h.open, h.options)
			h.cleanupCheck()
			if !r.Accepted || countOperation(h.events, "admission-stat") != 1 || len(h.events) != 3 {
				t.Fatal(r, e, h.events)
			}
			if size < 0 {
				if !errors.Is(e, os.ErrInvalid) {
					t.Fatal(e)
				}
			} else if e != nil || r.Declined != "eligibility" {
				t.Fatal(r, e)
			}
		})
	}
	t.Run("appledouble", func(t *testing.T) {
		h := newRecompressionHarness(t, bytes.Repeat([]byte("abcd"), 16384))
		h.options.Name = "._target"
		r, e := Recompress(t.Context(), h.open, h.options)
		h.cleanupCheck()
		if e != nil || r.Declined != "eligibility" || len(h.events) != 3 {
			t.Fatal(r, e, h.events)
		}
	})
	for _, decline := range []string{"content", "resource-fork"} {
		for _, fault := range []string{"", "data-sync", "times"} {
			t.Run(decline+"/"+fault, func(t *testing.T) {
				plain := bytes.Repeat([]byte("abcd"), 16384)
				if decline == "content" {
					state := uint32(0x12345678)
					for i := range plain {
						state ^= state << 13
						state ^= state >> 17
						state ^= state << 5
						plain[i] = byte(state)
					}
				}
				h := newRecompressionHarness(t, plain)
				h.fault = fault
				h.options.Encoding.ResourceForkOnly = true
				if decline == "resource-fork" {
					if e := os.WriteFile(filepath.Join(h.dir, "fork"), []byte("independent"), 0600); e != nil {
						t.Fatal(e)
					}
				}
				r, e := Recompress(t.Context(), h.open, h.options)
				h.cleanupCheck()
				if e != nil || !r.Accepted || r.Declined != decline || !r.Installation.Commit.Completed || r.Installation.Commit.Activated {
					t.Fatal(r, e, h.events)
				}
				if fault != "" && (len(r.Installation.Commit.Failures) != 1 || !errors.Is(r.Installation.Commit.Failures[0].Err, h.sentinel)) {
					t.Fatal("ignored restoration failure lost", r)
				}
				data, e := os.ReadFile(filepath.Join(h.dir, "data"))
				if e != nil || !bytes.Equal(data, plain) || h.attribute != nil || slices.Contains(h.events, "truncate") {
					t.Fatal("decline changed data", e, h.events)
				}
				if slices.Index(h.events, "fork-close") > slices.Index(h.events, "data-sync") {
					t.Fatal("decline cleanup order", h.events)
				}
			})
		}
	}
}

func TestRecompressFailuresAndCancellation(t *testing.T) {
	for _, cancelFault := range []bool{false, true} {
		for _, fault := range []string{"open", "admission-stat", "source-stat", "probe-write", "duplicate", "open-fork", "volume", "stage-create", "read", "fork-size", "fork-write", "fork-sync", "fork-close", "attribute", "truncate", "flags", "activate", "data-sync", "times", "stage-close", "close-stream", "close-input"} {
			t.Run(fmt.Sprintf("cancel-%t/%s", cancelFault, fault), func(t *testing.T) {
				h := newRecompressionHarness(t, bytes.Repeat([]byte("abcd"), 16384))
				h.options.Encoding.ResourceForkOnly = true
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				h.cancel = cancel
				if cancelFault {
					h.cancelAt = fault
				} else {
					h.fault = fault
				}
				r, e := Recompress(ctx, h.open, h.options)
				h.cleanupCheck()
				if !slices.Contains(h.events, fault) {
					t.Fatal("fault was not exercised", fault, h.events)
				}
				if !cancelFault {
					ignored := fault == "fork-sync" || fault == "fork-close" || fault == "data-sync" || fault == "times"
					if ignored {
						if e != nil || !r.Installation.Commit.Activated {
							t.Fatal("native ignored failure", r, e)
						}
					} else if !errors.Is(e, h.sentinel) {
						t.Fatal("lost failure", r, e, h.events)
					}
					if r.Accepted != (fault != "open" && fault != "admission-stat") {
						t.Fatal("queue admission", r, h.events)
					}
				} else if !errors.Is(e, context.Canceled) {
					t.Fatal("lost cancellation", r, e, h.events)
				}
				if cancelFault && slices.Contains(h.events, "truncate") && !r.Installation.Commit.Activated {
					t.Fatal("cancellation stranded empty unactivated data", r, h.events)
				}
			})
		}
	}
	for _, fault := range []string{"nil-input", "nil-stream", "nil-fork", "nil-stage", "invalid-mode"} {
		t.Run(fault, func(t *testing.T) {
			h := newRecompressionHarness(t, bytes.Repeat([]byte("abcd"), 16384))
			h.fault = fault
			r, e := Recompress(t.Context(), h.open, h.options)
			h.cleanupCheck()
			if !errors.Is(e, os.ErrInvalid) || r.Accepted != (fault != "nil-input") {
				t.Fatal(r, e, h.events)
			}
		})
	}
	t.Run("invalid-options", func(t *testing.T) {
		h := newRecompressionHarness(t, nil)
		for _, name := range []string{"a/b", "a\x00b"} {
			o := h.options
			o.Name = name
			if _, e := Recompress(t.Context(), h.open, o); !errors.Is(e, os.ErrInvalid) {
				t.Fatal(e)
			}
		}
		if _, e := Recompress(t.Context(), nil, h.options); !errors.Is(e, os.ErrInvalid) {
			t.Fatal(e)
		}
		o := h.options
		o.NewStage = nil
		if _, e := Recompress(t.Context(), h.open, o); !errors.Is(e, os.ErrInvalid) {
			t.Fatal(e)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, e := Recompress(ctx, h.open, h.options); !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
		if len(h.events) != 0 {
			t.Fatal("invalid options opened input", h.events)
		}
	})
}
