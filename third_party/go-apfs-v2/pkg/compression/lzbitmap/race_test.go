//go:build race

package lzbitmap

// raceEnabled reports that the race detector is instrumenting this build,
// which slows compression by more than an order of magnitude and makes
// any wall-clock bound meaningless.
const raceEnabled = true
