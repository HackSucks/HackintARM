package sandbox

// CaptureAppSandbox reads the current Darwin process's sandbox policy selector
// used by native xattr name defaults. It performs no policy change. Other hosts
// return errors.ErrUnsupported; logical operations accept the captured boolean.
func CaptureAppSandbox() (bool, error) { return captureAppSandbox() }
