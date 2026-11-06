package hostdata

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"golang.org/x/sys/unix"
)

// Race and storage failures are supplied per invocation; the existing ACL and
// cancellation suites still exercise the real descriptor-bound syscalls.
func TestReplacementLinuxAttributeFailures(t *testing.T) {
	steps := []string{"remove", "list-size", "list-read", "get-size", "get-read", "set"}
	for _, failing := range steps {
		t.Run(failing, func(t *testing.T) {
			source := heldfixture.Source(t, 0751)
			info, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			target := heldfixture.Source(t, 0600)
			var observed []string
			check := func(step string) error {
				observed = append(observed, step)
				if step == failing {
					return unix.EIO
				}
				return nil
			}
			attrs := replacementLinuxXattrs{
				remove: func(int, string) error { return check("remove") },
				list: func(_ int, out []byte) (int, error) {
					if out == nil {
						return len("user.test\x00"), check("list-size")
					}
					return copy(out, "user.test\x00"), check("list-read")
				},
				get: func(_ int, _ string, out []byte) (int, error) {
					if out == nil {
						return 1, check("get-size")
					}
					out[0] = 7
					return 1, check("get-read")
				},
				set: func(int, string, []byte, int) error { return check("set") },
			}
			if err = restoreReplacementLinux(context.Background(), source, target, info, attrs); !errors.Is(err, unix.EIO) {
				t.Fatalf("lost storage fault: %v", err)
			}
			for i, step := range steps {
				if step == failing && !reflect.DeepEqual(observed, steps[:i+1]) {
					t.Fatalf("operations after failure: %v", observed)
				}
			}
		})
	}
}

func TestReplacementLinuxAttributeBoundaries(t *testing.T) {
	for _, name := range []string{"unsupported", "missing-inherited-acl", "unsupported-inherited-acl", "oversized-list", "growing-list", "oversized-value", "growing-value", "cumulative-values", "cancel-absent-acl", "cancel-unsupported-acl", "cancel-unsupported-list"} {
		t.Run(name, func(t *testing.T) {
			source := heldfixture.Source(t, 0751)
			info, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			target := heldfixture.Source(t, 0600)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writes := 0
			attrs := replacementLinuxXattrs{
				remove: func(int, string) error {
					switch name {
					case "missing-inherited-acl":
						return unix.ENODATA
					case "unsupported-inherited-acl":
						return unix.ENOTSUP
					case "cancel-absent-acl":
						cancel()
						return unix.ENODATA
					case "cancel-unsupported-acl":
						cancel()
						return unix.ENOTSUP
					}
					return nil
				},
				list: func(_ int, out []byte) (int, error) {
					if name == "unsupported" {
						return 0, unix.ENOTSUP
					}
					if name == "cancel-unsupported-list" {
						cancel()
						return 0, unix.ENOTSUP
					}
					if out == nil {
						if name == "oversized-list" {
							return (8 << 20) + 1, nil
						}
						return len("user.first\x00user.second\x00"), nil
					}
					if name == "growing-list" {
						return len(out) + 1, nil
					}
					return copy(out, "user.first\x00user.second\x00"), nil
				},
				get: func(_ int, key string, out []byte) (int, error) {
					if out == nil {
						if name == "oversized-value" {
							return (8 << 20) + 1, nil
						}
						if name == "cumulative-values" && key == "user.first" {
							return 8 << 20, nil
						}
						return 1, nil
					}
					if name == "growing-value" {
						return len(out) + 1, nil
					}
					out[0] = 7
					return 1, nil
				},
				set: func(_ int, _ string, value []byte, _ int) error {
					if len(value) != 1 || value[0] != 7 {
						t.Fatalf("incorrect transferred attribute: %v", value)
					}
					writes++
					return nil
				},
			}
			err = restoreReplacementLinux(ctx, source, target, info, attrs)
			switch name {
			case "unsupported", "missing-inherited-acl", "unsupported-inherited-acl", "cumulative-values":
				if err != nil {
					t.Fatal(err)
				}
				got, e := target.Stat()
				if e != nil || got.Mode().Perm() != info.Mode().Perm() {
					t.Fatalf("mode not restored: %v %v", got, e)
				}
			case "cancel-absent-acl", "cancel-unsupported-acl", "cancel-unsupported-list":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation hidden: %v", err)
				}
			case "oversized-list", "oversized-value":
				if !errors.Is(err, ErrUnsupportedReplacement) {
					t.Fatalf("lost allocation boundary: %v", err)
				}
			default:
				if err == nil {
					t.Fatal("metadata growth accepted")
				}
			}
			wantWrites := 0
			if name == "missing-inherited-acl" || name == "unsupported-inherited-acl" {
				wantWrites = 2
			}
			if name == "cumulative-values" {
				wantWrites = 2
			}
			if writes != wantWrites {
				t.Fatalf("writes=%d want %d", writes, wantWrites)
			}
		})
	}
}

func TestReplacementLinuxClosedTarget(t *testing.T) {
	source := heldfixture.Source(t, 0600)
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	if err = restoreReplacementMetadataContext(context.Background(), source, target, info); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed target accepted: %v", err)
	}
}
