package hostdata

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestReplacementCopyStrategy(t *testing.T) {
	unavailable := errors.New("clone unavailable")
	failure := errors.New("failure")
	for _, tc := range []struct {
		name                              string
		clone, open, metadata             error
		wantClone, wantOpen, wantMetadata bool
	}{
		{"clone", nil, nil, nil, true, true, false},
		{"fallback", unavailable, nil, nil, false, true, true},
		{"authorization", os.ErrPermission, nil, nil, false, false, false},
		{"io", io.ErrUnexpectedEOF, nil, nil, false, false, false},
		{"clone-open", nil, failure, nil, true, true, false},
		{"fallback-open", unavailable, failure, nil, false, true, false},
		{"metadata", unavailable, nil, failure, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opened, copied bool
			var file *os.File
			result, err := prepareReplacementUsing(func() error { return tc.clone }, func(e error) bool { return errors.Is(e, unavailable) }, func(cloned bool) (*os.File, error) {
				opened = true
				if cloned != tc.wantClone {
					t.Fatalf("clone selection = %v", cloned)
				}
				if tc.open != nil {
					return nil, tc.open
				}
				var e error
				file, e = os.Create(filepath.Join(t.TempDir(), "stage"))
				return file, e
			}, func(f *os.File) error {
				copied = true
				if f != file {
					t.Fatal("wrong handle")
				}
				return tc.metadata
			})
			if opened != tc.wantOpen || copied != tc.wantMetadata {
				t.Fatalf("open=%v metadata=%v", opened, copied)
			}
			want := tc.metadata
			if tc.open != nil {
				want = tc.open
			}
			if !tc.wantOpen {
				want = tc.clone
			}
			if !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
			if err != nil {
				if result != nil {
					t.Fatal("returned failed stage")
				}
				if file != nil {
					if n, e := file.Write([]byte("closed-stage-probe")); n != 0 || !errors.Is(e, os.ErrClosed) {
						t.Fatalf("stage leaked: %v", e)
					}
				}
			} else {
				if result != file {
					t.Fatal("lost stage")
				}
				if e := result.Close(); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

type replacementTestFork struct {
	*os.File
	statErr, closeErr error
	closed            bool
}

func (f *replacementTestFork) Stat() (os.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	return f.File.Stat()
}
func (f *replacementTestFork) Close() error {
	f.closed = true
	return errors.Join(f.File.Close(), f.closeErr)
}

func TestReplacementCopyMetadata(t *testing.T) {
	failure := errors.New("injected failure")
	for _, step := range []string{"success", "no-fork", "list", "read", "missing", "write", "open-fork", "stat-fork", "transfer", "close-fork", "transfer-and-close", "birth", "budget"} {
		t.Run(step, func(t *testing.T) {
			file, err := os.Create(filepath.Join(t.TempDir(), "fork"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			payload := []byte("independent resource fork")
			if _, err := file.Write(payload); err != nil {
				t.Fatal(err)
			}
			fork := &replacementTestFork{File: file}
			if step == "stat-fork" {
				fork.statErr = failure
			}
			closeErr := fmt.Errorf("close: %w", io.ErrClosedPipe)
			if step == "close-fork" || step == "transfer-and-close" {
				fork.closeErr = closeErr
			}
			var calls []string
			record := func(name string) error {
				calls = append(calls, name)
				if step == name {
					return failure
				}
				return nil
			}
			var limits []int
			ops := replacementCopyOps{
				list: func() ([]string, error) {
					names := []string{"first", "empty", "com.apple.ResourceFork", "last"}
					if step == "no-fork" {
						names = []string{"first", "empty", "last"}
					}
					return names, record("list")
				},
				read: func(name string, limit int) ([]byte, bool, error) {
					limits = append(limits, limit)
					if step == "budget" && name == "empty" {
						if limit != 0 {
							t.Fatalf("remaining=%d", limit)
						}
						return nil, false, ErrXattrTooLarge
					}
					if err := record("read"); err != nil {
						return nil, false, err
					}
					if step == "missing" {
						return nil, false, nil
					}
					if step == "budget" {
						return make([]byte, MaxXattrReadSize), true, nil
					}
					if name == "empty" {
						return []byte{}, true, nil
					}
					return []byte(name), true, nil
				},
				write: func(name string, value []byte) error {
					if step != "budget" && !bytes.Equal(value, []byte(name)) && !(name == "empty" && len(value) == 0) {
						t.Fatal("value changed")
					}
					return record("write")
				},
				openFork: func() (replacementFork, error) {
					if err := record("open-fork"); err != nil {
						return nil, err
					}
					return fork, nil
				},
				replaceFork: func(value appledouble.Value) error {
					b := make([]byte, value.Size())
					if _, err := value.ReadAt(b, 0); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(b, payload) {
						t.Fatal("fork mismatch")
					}
					if step == "transfer-and-close" {
						return failure
					}
					return record("transfer")
				},
				birth: func() error { return record("birth") },
			}
			err = copyReplacementMetadataUsing(ops)
			want := failure
			switch step {
			case "success", "no-fork":
				want = nil
			case "missing":
				want = ErrXattrChanged
			case "budget":
				want = ErrXattrTooLarge
			case "close-fork":
				want = io.ErrClosedPipe
			}
			if !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v calls=%v", err, want, calls)
			}
			if step == "transfer-and-close" && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("lost close error")
			}
			opened := false
			for _, call := range calls {
				if call == "open-fork" && step != "open-fork" {
					opened = true
				}
			}
			if fork.closed != opened {
				t.Fatalf("closed=%v opened=%v", fork.closed, opened)
			}
			if want == nil {
				if !reflect.DeepEqual(limits, []int{MaxXattrReadSize, MaxXattrReadSize - 5, MaxXattrReadSize - 5}) {
					t.Fatalf("limits=%v", limits)
				}
				if calls[len(calls)-1] != "birth" {
					t.Fatalf("birth not last: %v", calls)
				}
			} else if step != "birth" && calls[len(calls)-1] == "birth" {
				t.Fatal("continued after metadata failure")
			}
		})
	}
}

func TestReplacementCopyLargeFork(t *testing.T) {
	const size int64 = 1<<32 + 37
	file, err := os.Create(filepath.Join(t.TempDir(), "large-fork"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := replacementSparse(file); err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	tail := []byte("beyond 32-bit offsets")
	if _, err := file.WriteAt(tail, size-int64(len(tail))); err != nil {
		t.Fatal(err)
	}
	fork := &replacementTestFork{File: file}
	called := false
	err = copyReplacementFork(replacementCopyOps{
		openFork: func() (replacementFork, error) { return fork, nil },
		replaceFork: func(value appledouble.Value) error {
			called = true
			if value.Size() != size {
				t.Fatalf("size truncated: %d", value.Size())
			}
			got := make([]byte, len(tail))
			if _, err := value.ReadAt(got, size-int64(len(tail))); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tail) {
				t.Fatalf("tail=%q", got)
			}
			if position, err := file.Seek(0, io.SeekCurrent); err != nil || position != 0 {
				t.Fatalf("source position changed: %d, %v", position, err)
			}
			return nil
		},
	})
	if err != nil || !called || !fork.closed {
		t.Fatalf("transfer=%v close=%v error=%v", called, fork.closed, err)
	}
}

// Raw copyfile applies quarantine policy, while replacement preserves the exact
// source bytes. Keep this independent native observation separate from the SDK
// contract, including the C control's clock interval and normalized agent.
type replacementNativeOutcome struct {
	CloneErrno       int   `json:"clone_errno"`
	CopyErrno        int   `json:"copy_errno"`
	CopyBegin        int64 `json:"copy_begin"`
	CopyEnd          int64 `json:"copy_end"`
	HostMajor        int   `json:"host_major"`
	ProcessInitCode  int   `json:"process_init_code"`
	ProcessInitErrno int   `json:"process_init_errno"`
	Raw              struct {
		Self struct {
			Code, Errno     int
			Flags           uint32
			Agent, Metadata string
			TrackingLength  int
		}
	}
}

func replacementNativeAttributes(t *testing.T, source, native map[string]string, outcome replacementNativeOutcome) {
	t.Helper()
	if len(source) != len(native) {
		t.Fatalf("native attribute count: %d want %d", len(native), len(source))
	}
	if outcome.CopyBegin <= 0 || outcome.CopyEnd < outcome.CopyBegin {
		t.Fatal("invalid native clock interval")
	}
	var profile appledouble.QuarantineProfile
	switch outcome.HostMajor {
	case 26:
		profile = appledouble.QuarantineMacOS26
	case 27:
		profile = appledouble.QuarantineMacOS27
	default:
		t.Fatalf("unqualified host profile %d", outcome.HostMajor)
	}
	process := &appledouble.QuarantineProcess{}
	rawProcess := outcome.Raw.Self
	if rawProcess.Code != 0 {
		// Darwin ENOATTR is 93. Absence needs the independent libquarantine control.
		if rawProcess.Code != -1 || rawProcess.Errno != 93 || outcome.ProcessInitCode != -1 || outcome.ProcessInitErrno != 93 {
			t.Fatalf("unqualified process absence: %+v", outcome)
		}
		process.Absent = true
	} else {
		if outcome.ProcessInitCode != 0 {
			t.Fatalf("inconsistent process controls: %+v", outcome)
		}
		agent, err := hex.DecodeString(rawProcess.Agent)
		if err != nil {
			t.Fatal(err)
		}
		process.Flags = rawProcess.Flags
		process.Agent = string(agent)
	}
	for name, value := range source {
		got, ok := native[name]
		if !ok {
			t.Fatalf("missing native attribute: %s", name)
		}
		if name != "com.apple.quarantine" {
			if got != value {
				t.Fatalf("native attribute mismatch: %s", name)
			}
			continue
		}
		raw, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		quarantine, err := appledouble.ParseQuarantineXattrWithProfile(raw, profile)
		if err != nil {
			t.Fatal(err)
		}
		applied, err := hex.DecodeString(got)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := appledouble.ParseQuarantineXattrWithProfile(applied, profile)
		if err != nil {
			t.Fatal(err)
		}
		clock := int64(parsed.Timestamp)
		if !process.Absent && (clock < outcome.CopyBegin || clock > outcome.CopyEnd) {
			t.Fatalf("quarantine clock %d outside %d..%d", clock, outcome.CopyBegin, outcome.CopyEnd)
		}
		plan, err := quarantine.PlanApplication(appledouble.QuarantineApplicationContext{Profile: profile, Process: process, Timestamp: parsed.Timestamp})
		if err != nil || !plan.Write || !bytes.Equal(plan.Value, applied) {
			t.Fatalf("native quarantine=%q plan=%+v error=%v context=%+v", applied, plan, err, outcome)
		}
		if value != hex.EncodeToString([]byte("0081;65000000;ReplacementTest;12345678-1234-1234-1234-123456789abc")) {
			t.Fatal("source quarantine changed")
		}
	}
	if _, ok := source["com.apple.quarantine"]; !ok {
		t.Fatal("quarantine control missing")
	}
}
