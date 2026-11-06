//go:build !profiler
// +build !profiler

// Profiler stub functions (no-op implementations when profiling is disabled)
package apfs

import "fmt"

// Profiler represents a performance profiler (stub when profiling is disabled)
type Profiler struct {
	// Empty struct when profiling is disabled
}

// NewProfiler creates a new profiler (no-op when profiling is disabled)
func NewProfiler() (*Profiler, error) {
	return &Profiler{}, nil
}

// Open opens the profiler output file (no-op when profiling is disabled)
func (p *Profiler) Open(filename string) error {
	if p == nil {
		return fmt.Errorf("invalid profiler")
	}
	return nil
}

// Close closes the profiler output file (no-op when profiling is disabled)
func (p *Profiler) Close() error {
	if p == nil {
		return fmt.Errorf("invalid profiler")
	}
	return nil
}

// StartTiming captures the start timestamp (no-op when profiling is disabled)
func (p *Profiler) StartTiming() (int64, error) {
	if p == nil {
		return 0, fmt.Errorf("invalid profiler")
	}
	return 0, nil
}

// StopTiming captures the stop timestamp (no-op when profiling is disabled)
func (p *Profiler) StopTiming(startTimestamp int64, name string, offset int64, size uint64) error {
	if p == nil {
		return fmt.Errorf("invalid profiler")
	}
	return nil
}
