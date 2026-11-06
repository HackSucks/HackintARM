package hostdata

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestResourceForkContextOwnership(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "fork-context-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	marker := errors.New("acquisition failure")
	for _, mode := range []string{"success", "cancel-before", "cancel-open", "open-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancel-before" {
				cancel()
			}
			var opened *os.File
			calls := 0
			fork, err := openResourceForkContextUsing(ctx, file, true, func(got context.Context, fd int, writable bool) (*os.File, error) {
				calls++
				if got != ctx || fd != int(file.Fd()) || !writable {
					t.Fatal("binding differs")
				}
				if mode == "open-failure" {
					return nil, marker
				}
				var e error
				opened, e = os.Open(file.Name())
				if mode == "cancel-open" {
					cancel()
				}
				return opened, e
			})
			switch mode {
			case "cancel-before":
				if calls != 0 || fork != nil || !errors.Is(err, context.Canceled) {
					t.Fatal(fork, err, calls)
				}
			case "cancel-open":
				if calls != 1 || fork != nil || !errors.Is(err, context.Canceled) {
					t.Fatal(fork, err, calls)
				}
				if e := opened.Close(); !errors.Is(e, os.ErrClosed) {
					t.Fatal("canceled fork leaked", e)
				}
			case "open-failure":
				if fork != nil || !errors.Is(err, marker) {
					t.Fatal(fork, err)
				}
			default:
				if err != nil || fork != opened {
					t.Fatal(fork, err)
				}
				if err = fork.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = file.Stat(); err != nil {
				t.Fatal("caller data handle closed", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = OpenResourceForkContext(ctx, file, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
