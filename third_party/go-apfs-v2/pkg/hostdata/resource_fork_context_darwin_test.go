package hostdata

import (
	"context"
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestNativeCompressionAcquisitionCancellationOwnership(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "canceled-open-")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input, err := openNativeCompressionInputUsing(ctx, "logical-name", func(name string, flags int, mode os.FileMode) (*os.File, error) {
		if name != "logical-name" || flags != os.O_RDWR || mode != 0 {
			t.Fatal("acquisition contract")
		}
		cancel()
		return file, nil
	})
	if input != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(input, err)
	}
	if err = file.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("native opener leaked after canceled binding", err)
	}
}

func TestResourceForkContextVersionRouting(t *testing.T) {
	for _, major := range []uint32{15, 26, 27} {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		calls := 0
		got, err := openResourceForkAtContextUsing(ctx, 7, "..namedfork/rsrc", unix.O_RDWR, 0600, func(observed context.Context) (osversion.Version, error) {
			if observed != ctx {
				t.Fatal("context not propagated")
			}
			return osversion.Version{Major: major}, nil
		}, func(fd int, name string, flags int, mode uint32) (int, error) {
			if major == 15 {
				t.Fatal("legacy route lost")
			}
			calls++
			return 42, nil
		}, func(fd, flags int, mode uint32) (int, error) {
			if major != 15 {
				t.Fatal("modern route lost")
			}
			calls++
			return 42, nil
		})
		if err != nil || got != 42 || calls != 1 {
			t.Fatal(major, got, err, calls)
		}
	}
	for _, when := range []string{"before", "after-detection"} {
		ctx, cancel := context.WithCancel(t.Context())
		if when == "before" {
			cancel()
		}
		defer cancel()
		got, err := openResourceForkAtContextUsing(ctx, 7, "..namedfork/rsrc", 0, 0, func(observed context.Context) (osversion.Version, error) {
			if when == "before" {
				t.Fatal("detect after cancellation")
			}
			cancel()
			return osversion.Version{Major: 27}, nil
		}, func(int, string, int, uint32) (int, error) { t.Fatal("acquired after cancellation"); return 0, nil }, func(int, int, uint32) (int, error) { t.Fatal("legacy acquisition after cancellation"); return 0, nil })
		if got != -1 || !errors.Is(err, context.Canceled) {
			t.Fatal(got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := openNativeResourceForkContext(ctx, -1, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestResourceForkLegacyContextCheckpoints(t *testing.T) {
	for _, cancelAfter := range []string{"before", "source-stat", "path", "open", "fork-stat", "truncate", "none"} {
		t.Run(cancelAfter, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if cancelAfter == "before" {
				cancel()
			}
			opened, closed, stats := false, 0, 0
			checkpoint := func(name string) {
				if err := ctx.Err(); err != nil {
					t.Fatal("native operation after cancellation", name)
				}
				if name == cancelAfter {
					cancel()
				}
			}
			calls := legacyForkCalls{
				stat: func(fd int, s *unix.Stat_t) error {
					stats++
					name := "source-stat"
					if stats == 2 {
						name = "fork-stat"
					}
					checkpoint(name)
					s.Mode = unix.S_IFREG
					s.Dev = 5
					s.Ino = 9
					return nil
				},
				path:     func(int) (string, error) { checkpoint("path"); return "/held", nil },
				open:     func(string, int, uint32) (int, error) { checkpoint("open"); opened = true; return 42, nil },
				truncate: func(int, int64) error { checkpoint("truncate"); return nil },
				close: func(fd int) error {
					closed++
					if fd != 42 {
						t.Fatal(fd)
					}
					return nil
				},
			}
			got, err := openLegacyResourceForkContextUsing(ctx, 7, unix.O_RDWR|unix.O_TRUNC, 0600, calls)
			if cancelAfter == "none" {
				if err != nil || got != 42 || closed != 0 {
					t.Fatal(got, err, closed)
				}
			} else {
				if !errors.Is(err, context.Canceled) || got != -1 {
					t.Fatal(got, err)
				}
				want := 0
				if opened {
					want = 1
				}
				if closed != want {
					t.Fatal("owned descriptor cleanup", closed, want)
				}
			}
		})
	}
}

func TestResourceForkNativeLateCancellationCloses(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "late-fork-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	acquired := -1
	fork, err := openNativeResourceForkContextUsing(ctx, int(file.Fd()), true, func(observed context.Context, fd int, name string, flags int, mode uint32) (int, error) {
		if observed != ctx || name != "..namedfork/rsrc" || flags != unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC || mode != 0600 {
			t.Fatal("native opening contract")
		}
		var e error
		acquired, e = unix.Dup(fd)
		cancel()
		return acquired, e
	})
	if fork != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(fork, err)
	}
	if _, err = unix.FcntlInt(uintptr(acquired), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("late canceled native descriptor leaked", err)
	}
	if _, err = file.Stat(); err != nil {
		t.Fatal("caller file closed", err)
	}
}

func TestResourceForkLegacyContextNativeBinding(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "legacy-context-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := openLegacyResourceForkContext(t.Context(), int(file.Fd()), unix.O_RDWR|unix.O_CREAT, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Close(fd); err != nil {
		t.Fatal(err)
	}
}
