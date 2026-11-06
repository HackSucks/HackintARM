package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

type compressionInstallFunctions struct {
	CompressionCommitBackend
	open func() (CompressionForkWriter, error)
	size func() (int64, error)
}

func (b compressionInstallFunctions) OpenCompressionFork() (CompressionForkWriter, error) {
	return b.open()
}
func (b compressionInstallFunctions) CompressionForkSize() (int64, error) { return b.size() }

func TestInstallCompressionForeignFiles(t *testing.T) {
	count := 0
	for index, c := range compressionLifecycleTrials(t) {
		if c.Fault != "" || c.Scenario != "ordinary" && c.Scenario != "multi-block" {
			continue
		}
		count++
		t.Run(fmt.Sprintf("%d/%s/%s/%s/%s", index, c.Filesystem, c.Scenario, c.Requested, c.Inline), func(t *testing.T) {
			root := t.TempDir()
			data, e := os.OpenFile(filepath.Join(root, "data"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if e != nil {
				t.Fatal(e)
			}
			defer data.Close()
			if _, e = data.Write(c.Data); e != nil {
				t.Fatal(e)
			}
			forkPath := filepath.Join(root, "foreign-resource-fork")
			mode := uint32(0100600)
			source := StatCopySource{Mode: mode, Flags: 0x8000, Times: FileTimes{Modify: time.Unix(1600000000, 123456789), Access: time.Unix(1550000000, 987654321)}}
			logical, e := NewLogicalMetadata(MetadataState{Stat: source, Security: SecurityCopySource{Mode: mode}})
			if e != nil {
				t.Fatal(e)
			}
			var attribute []byte
			committer := compressionCommitFunctions{
				compressionFlagFunctions: compressionFlagFunctions{read: logical.ReadFlags, compare: logical.CompareAndSwapFlags},
				attribute:                func(p []byte) error { attribute = bytes.Clone(p); return nil }, mode: logical.Chmod, truncate: data.Truncate, sync: data.Sync, times: logical.SetTimes,
			}
			var fork *os.File
			b := compressionInstallFunctions{CompressionCommitBackend: committer, open: func() (CompressionForkWriter, error) {
				var e error
				fork, e = os.OpenFile(forkPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				return fork, e
			}, size: func() (int64, error) {
				st, e := fork.Stat()
				if e != nil {
					return 0, e
				}
				return st.Size(), nil
			}}
			r, e := installHeldCompressionUsing(t.Context(), data, decmpfs.EncodedFile{Attribute: c.Attribute, ForkSize: int64(len(c.Fork))}, bytes.NewReader(c.Fork), source, func(got *os.File) (CompressionInstallationBackend, error) {
				if got != data {
					t.Fatal("redirected held file")
				}
				return b, nil
			})
			if e != nil || !r.Fork.Complete || !r.Commit.Activated || !r.Commit.Completed || len(r.Fork.Failures) != 0 || len(r.Commit.Failures) != 0 {
				t.Fatal(r, e)
			}
			// Windows Stat reports ERROR_INVALID_HANDLE after close. A nonempty
			// read uses Go's descriptor lifetime check on every host and must
			// fail as closed, rather than succeeding or returning ordinary EOF.
			var probe [1]byte
			if _, e = fork.ReadAt(probe[:], 0); !errors.Is(e, os.ErrClosed) {
				t.Fatal("fork ownership leaked", e)
			}
			st, e := data.Stat()
			if e != nil || st.Size() != 0 {
				t.Fatal("ordinary data fork not truncated", st, e)
			}
			got, e := os.ReadFile(forkPath)
			if e != nil || !bytes.Equal(got, c.Fork) || !bytes.Equal(attribute, c.Attribute) {
				t.Fatal("native storage differs", e)
			}
			state := logical.Snapshot().Stat
			if state.Flags != 0x8020 || state.Mode != mode || !state.Times.Modify.Equal(source.Times.Modify.Truncate(time.Microsecond)) || !state.Times.Access.Equal(source.Times.Access.Truncate(time.Microsecond)) {
				t.Fatal("foreign Darwin state differs", state)
			}
		})
	}
	if count != 66 {
		t.Fatal("incomplete independently captured storage inventory", count)
	}
}

func TestInstallCompressionStageFailures(t *testing.T) {
	storage, stage := compressionStagedFixture(t, 8)
	sentinel := errors.New("injected installation failure")
	for _, fault := range []string{"", "nil-backend", "invalid-mode", "negative-fork-size", "bad-storage", "cancel-before", "open", "nil-writer", "size", "cancel-open", "fork-write", "decline", "decline-sync", "decline-times", "cancel-decline", "cancel-fork-close", "attribute"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if fault == "cancel-before" {
				cancel()
			}
			var events []string
			fork := compressionForkFunctions{write: func(p []byte, _ int64) (int, error) {
				events = append(events, "write")
				if fault == "fork-write" {
					return 0, sentinel
				}
				return len(p), nil
			}, sync: func() error { events = append(events, "fork-sync"); return nil }, close: func() error {
				events = append(events, "fork-close")
				if fault == "cancel-fork-close" {
					cancel()
				}
				return nil
			}}
			backend := compressionInstallFunctions{CompressionCommitBackend: compressionCommitFunctions{
				compressionFlagFunctions: compressionFlagFunctions{read: func() (uint32, error) { events = append(events, "flags"); return 0, nil }, compare: func(a, b uint32) (uint32, error) { events = append(events, "cas"); return a, nil }},
				attribute: func([]byte) error {
					events = append(events, "attribute")
					if fault == "attribute" {
						return sentinel
					}
					return nil
				}, mode: func(uint16) error { t.Fatal("unexpected mode write"); return nil }, truncate: func(int64) error { events = append(events, "truncate"); return nil },
				sync: func() error {
					events = append(events, "data-sync")
					if fault == "decline-sync" {
						return sentinel
					}
					return nil
				}, times: func(time.Time, time.Time) error {
					events = append(events, "times")
					if fault == "cancel-decline" {
						cancel()
					}
					if fault == "decline-times" {
						return sentinel
					}
					return nil
				},
			}, open: func() (CompressionForkWriter, error) {
				events = append(events, "open")
				if fault == "open" {
					return nil, sentinel
				}
				if fault == "nil-writer" {
					return nil, nil
				}
				if fault == "cancel-open" {
					cancel()
				}
				return fork, nil
			}, size: func() (int64, error) {
				events = append(events, "size")
				if fault == "size" {
					return 0, sentinel
				}
				if fault == "decline" || fault == "decline-sync" || fault == "decline-times" || fault == "cancel-decline" {
					return 11, nil
				}
				return 0, nil
			}}
			var b CompressionInstallationBackend = backend
			s := storage
			source := StatCopySource{Mode: 0100600}
			switch fault {
			case "nil-backend":
				b = nil
			case "invalid-mode":
				source.Mode = 65536
			case "negative-fork-size":
				s.ForkSize = -1
			case "bad-storage":
				s.Attribute = nil
			}
			r, e := InstallCompression(ctx, s, bytes.NewReader(stage), source, b)
			declined := fault == "decline" || fault == "decline-sync" || fault == "decline-times" || fault == "cancel-decline"
			success := fault == "" || declined && fault != "cancel-decline"
			if (e == nil) != success || r.Fork.Declined != declined {
				t.Fatal(r, e, events)
			}
			contains := func(name string) bool {
				for _, v := range events {
					if v == name {
						return true
					}
				}
				return false
			}
			opened := contains("open") && fault != "open" && fault != "nil-writer"
			if contains("fork-close") != opened || contains("fork-sync") != opened {
				t.Fatal("fork cleanup", events)
			}
			if declined && (contains("write") || contains("attribute") || contains("truncate") || !contains("times") || !r.Commit.Completed) {
				t.Fatal("decline side effects", r, events)
			}
			if fault != "" && contains("truncate") {
				t.Fatal("failed installation truncated data", events)
			}
			if (fault == "decline-sync" || fault == "decline-times") && (len(r.Commit.Failures) != 1 || !errors.Is(r.Commit.Failures[0].Err, sentinel)) {
				t.Fatal(r)
			}
			if fault == "cancel-before" || fault == "cancel-open" || fault == "cancel-fork-close" || fault == "cancel-decline" {
				if !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestInstallHeldCompressionBindingFailures(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "bind-install-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e = InstallHeldCompression(ctx, f, decmpfs.EncodedFile{}, nil, StatCopySource{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = InstallHeldCompression(t.Context(), nil, decmpfs.EncodedFile{}, nil, StatCopySource{}); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	sentinel := errors.New("binding failed")
	if _, e = installHeldCompressionUsing(t.Context(), f, decmpfs.EncodedFile{}, nil, StatCopySource{}, func(got *os.File) (CompressionInstallationBackend, error) {
		if got != f {
			t.Fatal("wrong descriptor")
		}
		return nil, sentinel
	}); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
}
