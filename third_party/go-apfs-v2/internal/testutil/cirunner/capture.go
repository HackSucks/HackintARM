package cirunner

import (
	"errors"
	"io"
	"os"
)

// Capture retains stdout and stderr as separate, exclusively created files.
// Structured stdout must never include compiler, module-download or native-tool
// diagnostics. Both files are closed before success is returned. Partial output
// remains available after failures; existing evidence is never overwritten.
func (c *Cmd) Capture(stdout, stderr string) error {
	return c.capture(stdout, stderr, func(name string) (io.WriteCloser, error) {
		return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	})
}

func (c *Cmd) capture(stdout, stderr string, create func(string) (io.WriteCloser, error)) (result error) {
	if c.Stdout != nil || c.Stderr != nil {
		return errors.New("cirunner: capture output already configured")
	}
	out, err := create(stdout)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, out.Close()) }()
	diagnostic, err := create(stderr)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, diagnostic.Close()) }()
	c.Stdout, c.Stderr = out, diagnostic
	return c.Run()
}

// RunWithDiagnostics retains stderr separately when stdout is already configured
// for structured output, for example a JSON transcript and an in-memory parser.
// The diagnostic file is exclusive and closed before returning. Command and
// close failures are joined, and partial output remains available on failure.
func (c *Cmd) RunWithDiagnostics(path string) error {
	return c.runWithDiagnostics(path, func(name string) (io.WriteCloser, error) {
		return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	})
}

func (c *Cmd) runWithDiagnostics(path string, create func(string) (io.WriteCloser, error)) (result error) {
	if c.Stderr != nil {
		return errors.New("cirunner: diagnostics already configured")
	}
	diagnostic, err := create(path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, diagnostic.Close()) }()
	c.Stderr = diagnostic
	return c.Run()
}
