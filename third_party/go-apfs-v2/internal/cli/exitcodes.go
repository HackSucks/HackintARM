// Exit code contract for pipeline use.
package cli

import (
	"errors"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

// Exit codes. The contract lives in pkg/exitcode so that scripts, pipelines
// and the acceptance suite can depend on it without importing internal code.
const (
	ExitOK          = exitcode.OK
	ExitError       = exitcode.Error
	ExitUsage       = exitcode.Usage
	ExitBadImage    = exitcode.BadImage
	ExitAuth        = exitcode.Auth
	ExitUnsupported = exitcode.Unsupported
	ExitPartial     = exitcode.Partial
)

// codedError carries an exit code with an error.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// withCode wraps an error with an exit code.
func withCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

// usageErrorf returns a usage error (exit 2).
func usageErrorf(format string, args ...any) error {
	return withCode(ExitUsage, fmt.Errorf(format, args...))
}

// exitCodeFor extracts the exit code from an error (default 1).
func exitCodeFor(err error) int {
	if err == nil {
		return ExitOK
	}
	var coded *codedError
	if errors.As(err, &coded) {
		return coded.code
	}
	return ExitError
}
