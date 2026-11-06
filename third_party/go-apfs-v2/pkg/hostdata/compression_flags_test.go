package hostdata

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

type compressionFlagStep struct {
	Expected, Replacement, Actual uint32
	Errno                         int
}
type recordedCompressionFlags struct {
	t         *testing.T
	steps     []compressionFlagStep
	at, reads int
}

func (r *recordedCompressionFlags) ReadFlags() (uint32, error) {
	r.t.Helper()
	if r.at >= len(r.steps) {
		r.t.Fatal("read flags beyond native sequence")
	}
	r.reads++
	return r.steps[r.at].Expected, nil
}
func (r *recordedCompressionFlags) CompareAndSwapFlags(expected, replacement uint32) (uint32, error) {
	r.t.Helper()
	if r.at >= len(r.steps) {
		r.t.Fatal("comparison beyond native sequence")
	}
	s := r.steps[r.at]
	r.at++
	if s.Expected != expected || s.Replacement != replacement {
		r.t.Fatalf("native CAS %x->%x; Go %x->%x", s.Expected, s.Replacement, expected, replacement)
	}
	var err error
	if s.Errno != 0 {
		err = fmt.Errorf("native errno %d", s.Errno)
		if s.Errno == 35 {
			err = errors.Join(ErrStatFlagsAgain, err)
		}
	}
	return s.Actual, err
}

func TestActivateCompressionNativeComparisons(t *testing.T) {
	path := os.Getenv("APFS_COMPRESSION_LIFECYCLE_FIXTURE")
	if path == "" {
		path = "../../testdata/appledouble/native/compression-lifecycle.json.gz"
	}
	file, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	z, e := gzip.NewReader(file)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct {
		Schema int
		Cases  []struct {
			Filesystem, Scenario, Requested, Inline, Fault, Trace string
			FaultCount, FaultErrno                                int
			Observation                                           struct {
				TargetFlags uint32 `json:"target_flags"`
			}
		}
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != 591 {
		t.Fatal("incomplete native lifecycle corpus")
	}
	exercised := 0
	for _, c := range corpus.Cases {
		var steps []compressionFlagStep
		pending := false
		nativeError := 0
		for _, line := range strings.Split(strings.TrimSpace(c.Trace), "\n") {
			if line == "" {
				continue
			}
			var event struct {
				Operation                     string
				Expected, Replacement, Actual uint32
				Errno                         int
			}
			if e = json.Unmarshal([]byte(line), &event); e != nil {
				t.Fatal(e)
			}
			switch event.Operation {
			case "ffsctl":
				if pending {
					t.Fatal("missing native CAS arguments")
				}
				pending = true
				nativeError = event.Errno
			case "cas-flags":
				if !pending {
					t.Fatal("missing native CAS result")
				}
				pending = false
				steps = append(steps, compressionFlagStep{event.Expected, event.Replacement, event.Actual, nativeError})
			}
		}
		if pending {
			t.Fatal("incomplete native CAS trace")
		}
		if len(steps) == 0 {
			continue
		} // Earlier native eligibility/installation did not reach activation.
		exercised++
		t.Run(fmt.Sprintf("%s/%s/%s/%s/%s/%d/%d", c.Filesystem, c.Scenario, c.Requested, c.Inline, c.Fault, c.FaultCount, c.FaultErrno), func(t *testing.T) {
			backend := &recordedCompressionFlags{t: t, steps: steps}
			result, e := ActivateCompression(t.Context(), backend)
			applied := c.Observation.TargetFlags&UFCompressed != 0
			if result.Applied != applied || (e == nil) != applied || backend.at != len(steps) || backend.reads != len(steps) || result.Comparisons != len(steps) || result.Reads != len(steps) {
				t.Fatal(result, e, applied, backend)
			}
			failures := 0
			for _, s := range steps {
				if s.Errno != 0 {
					failures++
				}
			}
			if len(result.Failures) != failures {
				t.Fatal("lost native failure history", result)
			}
		})
	}
	if exercised != 272 {
		t.Fatal("incomplete native activation inventory", exercised)
	}
}

type compressionFlagFunctions struct {
	read    func() (uint32, error)
	compare func(uint32, uint32) (uint32, error)
}

func (b compressionFlagFunctions) ReadFlags() (uint32, error) { return b.read() }
func (b compressionFlagFunctions) CompareAndSwapFlags(a, c uint32) (uint32, error) {
	return b.compare(a, c)
}

func TestActivateCompressionCancellationAndReadFailures(t *testing.T) {
	sentinel := errors.New("flag read failed")
	for _, where := range []string{"before", "read", "between", "second-read"} {
		t.Run(where, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if where == "before" {
				cancel()
			}
			reads, comparisons := 0, 0
			backend := compressionFlagFunctions{
				read: func() (uint32, error) {
					reads++
					if where == "read" || (where == "second-read" && reads == 2) {
						return 0, sentinel
					}
					if where == "between" {
						cancel()
					}
					return 0x8000, nil
				},
				compare: func(a, b uint32) (uint32, error) {
					comparisons++
					if a != 0x8000 || b != 0x8020 {
						t.Fatal(a, b)
					}
					return 0, ErrStatFlagsAgain
				},
			}
			result, e := ActivateCompression(ctx, backend)
			want := context.Canceled
			if where == "read" || where == "second-read" {
				want = sentinel
			}
			if !errors.Is(e, want) || result.Applied || result.Reads != reads || result.Comparisons != comparisons {
				t.Fatal(result, e)
			}
			if (where == "before" && reads != 0) || (where == "between" && comparisons != 0) || (where == "second-read" && comparisons != 1) {
				t.Fatal("incorrect cancellation/failure boundary", result)
			}
		})
	}
	if _, e := ActivateCompression(t.Context(), nil); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	logical, e := NewLogicalMetadata(MetadataState{})
	if e != nil {
		t.Fatal(e)
	}
	result, e := ActivateCompression(t.Context(), logical)
	if e != nil || !result.Applied || logical.Snapshot().Stat.Flags != UFCompressed {
		t.Fatal(result, e)
	}
}
