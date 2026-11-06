package diskimage

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"
	"time"
)

func TestDetachRetryPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		busy, code, attempts, pauses int
		want                         error
	}{
		{name: "success", attempts: 1},
		{name: "busy then success", busy: 3, attempts: 4, pauses: 3},
		{name: "exhausted", busy: 10, attempts: 10, pauses: 9, want: io.ErrClosedPipe},
		{name: "nonbusy failure", code: 1, attempts: 1, want: io.ErrClosedPipe},
		{name: "launch failure", code: -1, attempts: 1, want: io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, pauses := 0, 0
			err := retryDetach(context.Background(), func() (int, error) {
				calls++
				if calls <= tc.busy {
					return 16, io.ErrClosedPipe
				}
				if tc.code != 0 {
					return tc.code, io.ErrClosedPipe
				}
				return 0, nil
			}, func(ctx context.Context, d time.Duration) error {
				pauses++
				if d != time.Second {
					t.Fatal(d)
				}
				return ctx.Err()
			})
			if !errors.Is(err, tc.want) || calls != tc.attempts || pauses != tc.pauses {
				t.Fatal(err, calls, pauses)
			}
		})
	}
}
func TestDetachCancellationAndValidation(t *testing.T) {
	operation := func() (int, error) { return 0, nil }
	//nolint:staticcheck // Verify nil-context rejection at the public boundary.
	if err := RetryDetach(nil, operation); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if err := RetryDetach(context.Background(), nil); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if err := RetryDetach(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RetryDetach(ctx, func() (int, error) { t.Fatal("called after cancellation"); return 0, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	err := RetryDetach(ctx, func() (int, error) { cancel(); return 16, io.ErrClosedPipe })
	if !errors.Is(err, context.Canceled) || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err := wait(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := RetryDetach(context.Background(), func() (int, error) { return 16, nil }); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}
