package hostdata

// darwinSizeResult retains the ssize_t-width value from the typed wrapper and
// the existing zero-on-error contract. Errno is captured by the Go runtime in
// the wrapper call; no later thread-local errno query or generic FFI is used.
func darwinSizeResult(value int64, err error) (int, error) {
	if err != nil {
		return 0, err
	}
	return int(value), nil
}
