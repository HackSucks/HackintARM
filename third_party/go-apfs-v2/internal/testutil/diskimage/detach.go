// Package diskimage supplies test-harness lifecycle helpers, never image codecs.
package diskimage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"
)

// RetryDetach retries hdiutil's resource-busy exit status (16) up to ten times,
// waiting one second between attempts. The operation must record each command's
// stdout, stderr and exit status before returning. It must perform an ordinary
// detach, never force ejection. Other failures and exhaustion remain errors.
func RetryDetach(ctx context.Context, operation func() (int, error)) error {
	return retryDetach(ctx, operation, wait)
}
func retryDetach(ctx context.Context, operation func() (int, error), pause func(context.Context, time.Duration) error) error {
	if ctx == nil || operation == nil {
		return fs.ErrInvalid
	}
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		code, err := operation()
		if err == nil {
			if code != 0 {
				return fmt.Errorf("detach exit %d without command error: %w", code, fs.ErrInvalid)
			}
			return nil
		}
		if code != 16 || attempt == 10 {
			return fmt.Errorf("detach failed after %d attempt(s): %w", attempt, err)
		}
		if e := pause(ctx, time.Second); e != nil {
			return errors.Join(err, e)
		}
	}
}
func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
