package hostdata

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// This boundary supplies captured Darwin effects while using actual host files.
// It qualifies the common lifecycle on all three operating systems; the native
// C replay separately verifies the Darwin binding rather than trusting this model.
func pathQualification(t *testing.T) *appleDoublePath {
	t.Helper()
	dir := t.TempDir()
	p := &appleDoublePath{ctx: context.Background(), sourceName: filepath.Join(dir, "source"), destinationName: filepath.Join(dir, "destination"), options: AppleDoublePathOptions{Operation: PathPackAppleDouble, Pack: DefaultObjectPackOptions(), Unpack: DefaultObjectUnpackOptions(), MaxOpenAttempts: 4}, result: &AppleDoublePathResult{}, access: defaultPathAccessOps()}
	for _, name := range []string{p.sourceName, p.destinationName} {
		if e := os.WriteFile(name, []byte("payload"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	source, target := objectFixture(t), objectFixture(t)
	// The native boundary uses Darwin dev/inode observations. On Windows,
	// model those observations from the same real host identities, rather than
	// pretending a Windows FileInfo contains a Darwin stat structure.
	sourceInfo, e := os.Stat(p.sourceName)
	if e != nil {
		t.Fatal(e)
	}
	targetInfo, e := os.Stat(p.destinationName)
	if e != nil {
		t.Fatal(e)
	}
	identity := func(info os.FileInfo) (LinkIdentity, bool) {
		if id, ok := Link(info); ok {
			return id, true
		}
		if os.SameFile(info, sourceInfo) {
			return LinkIdentity{Device: 1, Inode: 1}, true
		}
		if os.SameFile(info, targetInfo) {
			return LinkIdentity{Device: 1, Inode: 2}, true
		}
		return LinkIdentity{}, false
	}
	object := func(name string) *AppleDoubleObject {
		if name == p.sourceName {
			return source
		}
		return target
	}
	p.native = pathNativeOps{
		supported: true,
		identity:  identity,
		heldMeta:  func(f *os.File) (objectMetadata, error) { return object(f.Name()).meta, nil },
		capture: func(name string, nofollow bool) (PathMetadata, error) {
			info, e := pathInfo(name, nofollow)
			if e != nil {
				return PathMetadata{}, e
			}
			security, state, e := object(name).meta.CaptureSecurityState()
			id, _ := identity(info)
			return PathMetadata{State: MetadataState{Security: security, Stat: state}, Identity: id, Size: info.Size()}, e
		},
		bind: func(_ context.Context, file *os.File) (*AppleDoubleObject, error) { return object(file.Name()), nil },
		identities: func(context.Context) (*appledouble.ACLIdentityCapture, error) {
			return appledouble.NewACLIdentityCapture(func(appledouble.ACLIdentity) ([16]byte, error) { return [16]byte{7}, nil }, nil), nil
		},
		singleWriter: func(*os.File) error { return nil },
		protection:   func(*os.File) (bool, error) { return false, nil },
		getClass:     func(*os.File) (int, error) { return 3, nil },
		setClass:     func(*os.File, int) error { return nil },
	}
	t.Cleanup(func() {
		for _, s := range p.Close() {
			if s.Err != nil {
				t.Errorf("cleanup %s: %v", s.Operation, s.Err)
			}
		}
	})
	return p
}

// File.Stat on a closed handle reports the host's underlying error. Windows
// reports ERROR_INVALID_HANDLE here, while Close itself reports os.ErrClosed.
// Observe the independent standard-library call and require preservation of
// that exact cause rather than changing the production error to fit a test.
func closedPathStatCause(t *testing.T) error {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "closed-stat-")
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = file.Stat()
	var pathError *os.PathError
	if !errors.As(err, &pathError) || pathError.Err == nil {
		t.Fatalf("closed Stat did not retain an OS failure: %v", err)
	}
	return pathError.Err
}

func TestAppleDoublePathValidationAndIdentity(t *testing.T) {
	p := pathQualification(t)
	for _, tc := range []struct {
		name   string
		change func(*AppleDoublePathOptions)
		ctx    context.Context
		source string
	}{
		{"nil-context", func(*AppleDoublePathOptions) {}, nil, p.sourceName},
		{"empty-source", func(*AppleDoublePathOptions) {}, p.ctx, ""},
		{"zero-budget", func(o *AppleDoublePathOptions) { o.MaxOpenAttempts = 0 }, p.ctx, p.sourceName},
		{"operation", func(o *AppleDoublePathOptions) { o.Operation = 99 }, p.ctx, p.sourceName},
		{"missing-logical-source", func(o *AppleDoublePathOptions) { o.Captured = &CapturedPathContext{} }, p.ctx, p.sourceName},
		{"invented-quarantine", func(o *AppleDoublePathOptions) { o.Pack.HasQuarantine = true }, p.ctx, p.sourceName},
		{"invented-sandbox", func(o *AppleDoublePathOptions) { o.Operation = PathUnpackAppleDouble; o.Unpack.Sandboxed = true }, p.ctx, p.sourceName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := p.options
			tc.change(&o)
			r, e := copyAppleDoublePath(tc.ctx, tc.source, p.destinationName, o, p.native)
			if !errors.Is(e, os.ErrInvalid) || r.Lifecycle.Code != -1 {
				t.Fatal(r, e)
			}
		})
	}
	n := p.native
	n.supported = false
	if _, e := copyAppleDoublePath(p.ctx, p.sourceName, p.destinationName, p.options, n); !errors.Is(e, errors.ErrUnsupported) {
		t.Fatal(e)
	}
	same, e := p.SameObject()
	if e != nil || same {
		t.Fatal(same, e)
	}
	p.destinationName = p.sourceName
	if same, e = p.SameObject(); e != nil || !same {
		t.Fatal(same, e)
	}
	r, e := copyAppleDoublePath(p.ctx, p.sourceName, p.sourceName, p.options, p.native)
	if e != nil || !r.Lifecycle.Completed {
		t.Fatal(r, e)
	}
	p.options.Exclusive = true
	if _, e = copyAppleDoublePath(p.ctx, p.sourceName, p.sourceName, p.options, p.native); !errors.Is(e, os.ErrExist) {
		t.Fatal(e)
	}
	p.sourceName += "-missing"
	if _, e = p.SameObject(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}

func TestAppleDoublePathAcquisitionFailures(t *testing.T) {
	marker := errors.New("injected host boundary failure")
	closedStat := closedPathStatCause(t)
	for _, tc := range []struct {
		name   string
		change func(*appleDoublePath)
		want   error
	}{
		{"source-security", func(p *appleDoublePath) {
			p.native.capture = func(string, bool) (PathMetadata, error) { return PathMetadata{}, marker }
		}, marker},
		{"unsupported-kind", func(p *appleDoublePath) {
			old := p.native.capture
			p.native.capture = func(n string, b bool) (PathMetadata, error) {
				v, e := old(n, b)
				v.State.Stat.Mode = 0010600
				return v, e
			}
		}, errors.ErrUnsupported},
		{"initial-stat", func(p *appleDoublePath) {
			p.access.info = func(string, bool) (os.FileInfo, error) { return nil, marker }
		}, marker},
		{"source-open", func(p *appleDoublePath) {
			p.access.open = func(string, int, uint32, bool, bool, int) (*os.File, error) { return nil, marker }
		}, marker},
		{"held-stat", func(p *appleDoublePath) {
			old := p.access.open
			p.access.open = func(n string, f int, m uint32, a, b bool, c int) (*os.File, error) {
				v, e := old(n, f, m, a, b, c)
				if e == nil {
					if e = v.Close(); e != nil {
						t.Fatal(e)
					}
				}
				return v, e
			}
		}, closedStat},
		{"held-identity", func(p *appleDoublePath) {
			old := p.access.open
			p.access.open = func(_ string, f int, m uint32, a, b bool, c int) (*os.File, error) {
				return old(p.destinationName, f, m, a, false, c)
			}
		}, ErrMetadataIdentity},
		{"captured-identity", func(p *appleDoublePath) {
			old := p.native.capture
			p.native.capture = func(n string, b bool) (PathMetadata, error) { v, e := old(n, b); v.Identity.Inode++; return v, e }
		}, ErrMetadataIdentity},
		{"repeat-stat", func(p *appleDoublePath) {
			old := p.access.info
			count := 0
			p.access.info = func(n string, b bool) (os.FileInfo, error) {
				count++
				if count == 2 {
					return nil, marker
				}
				return old(n, b)
			}
		}, marker},
		{"repeat-type", func(p *appleDoublePath) {
			old := p.access.info
			count := 0
			p.access.info = func(n string, b bool) (os.FileInfo, error) {
				count++
				if count == 2 {
					return os.Stat(filepath.Dir(n))
				}
				return old(n, b)
			}
		}, ErrMetadataIdentity},
		{"source-bind", func(p *appleDoublePath) {
			p.native.bind = func(context.Context, *os.File) (*AppleDoubleObject, error) { return nil, marker }
		}, marker},
		{"unlink", func(p *appleDoublePath) {
			p.options.UnlinkDestination = true
			p.access.unlink = func(string) error { return marker }
		}, marker},
		{"source-volume", func(p *appleDoublePath) { p.native.protection = func(*os.File) (bool, error) { return false, marker } }, marker},
		{"source-class", func(p *appleDoublePath) {
			p.native.protection = func(*os.File) (bool, error) { return true, nil }
			p.native.getClass = func(*os.File) (int, error) { return 0, marker }
		}, marker},
		{"destination-open", func(p *appleDoublePath) {
			old := p.access.open
			p.access.open = func(n string, f int, m uint32, a, b bool, c int) (*os.File, error) {
				if n == p.destinationName {
					return nil, marker
				}
				return old(n, f, m, a, b, c)
			}
		}, marker},
		{"destination-bind", func(p *appleDoublePath) {
			old := p.native.bind
			p.native.bind = func(c context.Context, f *os.File) (*AppleDoubleObject, error) {
				if f.Name() == p.destinationName {
					return nil, marker
				}
				return old(c, f)
			}
		}, marker},
		{"destination-volume", func(p *appleDoublePath) {
			p.native.protection = func(f *os.File) (bool, error) {
				if f.Name() == p.destinationName {
					return false, marker
				}
				return true, nil
			}
		}, marker},
		{"destination-class", func(p *appleDoublePath) {
			p.native.protection = func(*os.File) (bool, error) { return true, nil }
			p.native.setClass = func(*os.File, int) error { return marker }
		}, marker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pathQualification(t)
			tc.change(p)
			_, e := p.Open(p.ctx, 4)
			if !errors.Is(e, tc.want) {
				t.Fatalf("wanted %v, got %v", tc.want, e)
			}
			steps := p.Close()
			for _, s := range steps {
				if s.Err != nil && tc.name != "held-stat" {
					t.Fatal(s)
				}
			}
			if p.sourceFile != nil || p.destinationFile != nil || len(p.Close()) != 0 {
				t.Fatal("handle ownership not released")
			}
			if data, e := os.ReadFile(p.sourceName); e != nil || string(data) != "payload" {
				t.Fatal("source altered", string(data), e)
			}
		})
	}
}

func TestAppleDoublePathOpenRetryPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failures  []error
		exclusive bool
		operation PathAppleDoubleOperation
		error     error
	}{
		{name: "existing", failures: []error{syscall.EEXIST}},
		{name: "exclusive-existing", failures: []error{syscall.EEXIST}, exclusive: true, error: syscall.EEXIST},
		{name: "permission-is-fatal", failures: []error{syscall.EACCES}, error: syscall.EACCES},
		{name: "repeated-existence-budget", failures: []error{syscall.EEXIST, syscall.EEXIST, syscall.EEXIST, syscall.EEXIST}, error: ErrPathWorkLimit},
		{name: "directory-retry", failures: []error{syscall.EISDIR}},
		{name: "exclusive-directory-pack", failures: []error{syscall.EISDIR}, exclusive: true, error: syscall.EISDIR},
		{name: "exclusive-directory-unpack", failures: []error{syscall.EISDIR}, exclusive: true, operation: PathUnpackAppleDouble},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pathQualification(t)
			p.options.Exclusive = tc.exclusive
			if tc.operation != 0 {
				p.options.Operation = tc.operation
			}
			old := p.access.open
			var flags []int
			calls := 0
			p.access.open = func(n string, f int, m uint32, a, b bool, c int) (*os.File, error) {
				if n != p.destinationName {
					return old(n, f, m, a, b, c)
				}
				flags = append(flags, f)
				calls++
				if calls <= len(tc.failures) {
					return nil, tc.failures[calls-1]
				}
				return os.OpenFile(n, os.O_RDWR, 0600)
			}
			r, e := p.Open(p.ctx, 4)
			if !errors.Is(e, tc.error) || r.PermissionsChanged {
				t.Fatal(r, e)
			}
			if errors.Is(tc.error, syscall.EACCES) && calls != 1 {
				t.Fatal("permission failure was retried", calls)
			}
			if len(flags) > 1 && errors.Is(tc.failures[0], syscall.EEXIST) && flags[1]&os.O_CREATE != 0 {
				t.Fatal("retried creation after EEXIST", flags)
			}
			if len(flags) > 1 && errors.Is(tc.failures[0], syscall.EISDIR) && flags[1]&(os.O_CREATE|os.O_WRONLY|os.O_TRUNC) != 0 {
				t.Fatal("writable directory retry", flags)
			}
		})
	}
}

func TestAppleDoublePathCancellationReleasesOwnedFiles(t *testing.T) {
	for _, at := range []string{"quarantine", "destination-open"} {
		t.Run(at, func(t *testing.T) {
			p := pathQualification(t)
			ctx, cancel := context.WithCancel(p.ctx)
			defer cancel()
			if at == "quarantine" {
				old := p.native.bind
				p.native.bind = func(c context.Context, f *os.File) (*AppleDoubleObject, error) {
					v, e := old(c, f)
					cancel()
					return v, e
				}
			} else {
				old := p.access.open
				p.access.open = func(n string, f int, m uint32, a, b bool, c int) (*os.File, error) {
					if n == p.destinationName {
						cancel()
						return nil, syscall.EEXIST
					}
					return old(n, f, m, a, b, c)
				}
			}
			_, e := p.Open(ctx, 4)
			if !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			for _, s := range p.Close() {
				if s.Err != nil {
					t.Fatal(s)
				}
			}
			for _, n := range []string{p.sourceName, p.destinationName} {
				if e = os.Remove(n); e != nil {
					t.Fatal("owned handle retained", e)
				}
			}
		})
	}
}

func TestAppleDoublePathProtectionObservations(t *testing.T) {
	p := pathQualification(t)
	p.options.Captured = pathCapturedFixture(t, objectFixture(t), objectFixture(t))
	p.options.Captured.SourceProtection = nil
	if _, _, e := p.sourceProtection(); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	p.options.Captured.SourceProtection = &CapturedPathProtection{Supported: true, Class: 7}
	if supported, class, e := p.sourceProtection(); e != nil || !supported || class != 7 {
		t.Fatal(supported, class, e)
	}
	p.options.Captured.DestinationProtection = nil
	if e := p.destinationProtection(7, true); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	p.options.Captured.DestinationProtection = &CapturedPathProtection{Supported: true, Class: 2}
	if e := p.destinationProtection(7, false); e != nil || p.options.Captured.DestinationProtection.Class != 2 {
		t.Fatal(e)
	}
	if e := p.destinationProtection(7, true); e != nil || p.options.Captured.DestinationProtection.Class != 7 {
		t.Fatal(e)
	}
	p.options.Captured = nil
	p.options.DontSetProtection = true
	p.native.protection = func(*os.File) (bool, error) { return true, nil }
	p.native.getClass = func(*os.File) (int, error) { t.Fatal("queried forbidden class"); return 0, nil }
	if supported, class, e := p.sourceProtection(); !supported || class != -1 || e != nil {
		t.Fatal(supported, class, e)
	}
	if got := pathFileMode(07777); got != (0777 | os.ModeSetuid | os.ModeSetgid | os.ModeSticky) {
		t.Fatal(got)
	}
}

func TestAppleDoublePathClosePreservesBothErrors(t *testing.T) {
	p := pathQualification(t)
	var e error
	p.sourceFile, e = os.Open(p.sourceName)
	if e != nil {
		t.Fatal(e)
	}
	p.destinationFile, e = os.Open(p.destinationName)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range []*os.File{p.sourceFile, p.destinationFile} {
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
	}
	steps := p.Close()
	var names []string
	for _, s := range steps {
		names = append(names, s.Operation)
		if !errors.Is(s.Err, os.ErrClosed) {
			t.Fatal(s)
		}
	}
	if !reflect.DeepEqual(names, []string{"close-source", "close-destination"}) {
		t.Fatal(names)
	}
}

func TestAppleDoublePathNativeBoundaryRoundTrip(t *testing.T) {
	p := pathQualification(t)
	r, e := copyAppleDoublePath(p.ctx, p.sourceName, p.destinationName, p.options, p.native)
	if e != nil || !r.Lifecycle.Completed {
		t.Fatal(r, e)
	}
	if r.Pack.Code != 0 {
		t.Fatal(fmt.Sprint(r.Pack))
	}
}

func TestAppleDoublePathDirectoryAndLinkAcquisition(t *testing.T) {
	for _, kind := range []string{"directory", "link"} {
		for _, fault := range []string{"none", "create", "open", "readlink", "exclusive"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				p := pathQualification(t)
				p.options.Operation = PathUnpackAppleDouble
				p.options.NoFollowSource = true
				if e := os.Remove(p.sourceName); e != nil {
					t.Fatal(e)
				}
				if e := os.Remove(p.destinationName); e != nil {
					t.Fatal(e)
				}
				if kind == "directory" {
					if e := os.Mkdir(p.sourceName, 0700); e != nil {
						t.Fatal(e)
					}
				} else {
					if e := os.Symlink("missing-target", p.sourceName); e != nil {
						t.Fatal(e)
					}
				}
				capture := p.native.capture
				p.native.capture = func(n string, b bool) (PathMetadata, error) {
					v, e := capture(n, b)
					if kind == "directory" {
						v.State.Stat.Mode = 0040750
					} else {
						v.State.Stat.Mode = 0120750
					}
					return v, e
				}
				marker := errors.New("creation effect refused")
				switch fault {
				case "create":
					p.access.mkdir = func(string, os.FileMode) error { return marker }
					p.access.symlink = func(string, string) error { return marker }
				case "open":
					old := p.access.open
					p.access.open = func(n string, f int, m uint32, a, b bool, c int) (*os.File, error) {
						if n == p.destinationName {
							return nil, marker
						}
						return old(n, f, m, a, b, c)
					}
				case "readlink":
					p.access.readlink = func(string) (string, error) { return "", marker }
				case "exclusive":
					p.options.Exclusive = true
					p.access.mkdir = func(string, os.FileMode) error { return os.ErrExist }
					p.access.symlink = func(string, string) error { return os.ErrExist }
				}
				_, e := p.Open(p.ctx, 4)
				want := error(nil)
				if fault == "create" || fault == "open" || (fault == "readlink" && kind == "link") {
					want = marker
				}
				if fault == "exclusive" {
					want = os.ErrExist
				}
				if !errors.Is(e, want) {
					t.Fatalf("wanted %v, got %v", want, e)
				}
				if e == nil {
					info, e := os.Lstat(p.destinationName)
					if e != nil {
						t.Fatal(e)
					}
					if kind == "directory" && !info.IsDir() {
						t.Fatal(info.Mode())
					}
					if kind == "link" && info.Mode()&os.ModeSymlink == 0 {
						t.Fatal(info.Mode())
					}
				}
			})
		}
	}
}

func TestAppleDoublePathCapturedCreationAndPartialFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*appleDoublePath)
		want   error
	}{
		{"missing-source", func(p *appleDoublePath) {
			if e := os.Remove(p.sourceName); e != nil {
				t.Fatal(e)
			}
		}, os.ErrNotExist},
		{"uncaptured-existing", func(p *appleDoublePath) { p.options.Captured.Destination = nil }, os.ErrInvalid},
		{"uncaptured-creation", func(p *appleDoublePath) {
			if e := os.Remove(p.destinationName); e != nil {
				t.Fatal(e)
			}
			p.options.Captured.Creation = nil
		}, os.ErrInvalid},
		{"invalid-creation", func(p *appleDoublePath) {
			if e := os.Remove(p.destinationName); e != nil {
				t.Fatal(e)
			}
			p.options.Captured.Creation.Template.Identities.Version = 0
		}, appledouble.ErrACLIdentitySnapshot},
		{"unlink-create", func(p *appleDoublePath) { p.options.UnlinkDestination = true }, nil},
		{"unlink-missing", func(p *appleDoublePath) {
			p.options.UnlinkDestination = true
			if e := os.Remove(p.destinationName); e != nil {
				t.Fatal(e)
			}
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pathQualification(t)
			p.options.Captured = pathCapturedFixture(t, objectFixture(t), objectFixture(t))
			tc.change(p)
			_, e := p.Open(p.ctx, 4)
			if !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
		})
	}
	p := pathQualification(t)
	p.options.Captured = pathCapturedFixture(t, objectFixture(t), nil)
	if _, e := p.capture(p.destinationName, false, true); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	p.sourceMetadata.State.Stat.Mode = 0040555
	p.options.Captured.Creation.ParentACL = &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1 | 64, Rights: 2, Principal: [16]byte{9}}}}
	p.options.Captured.Creation.Template.State.Security.Properties.RawSecurity = &appledouble.FileSecurity{OwnerUUID: [16]byte{4}, ACL: &appledouble.ACL{}}
	if e := p.createCapturedDestination(0040000); e != nil {
		t.Fatal(e)
	}
	state, _, e := p.options.Captured.Destination.LogicalSnapshot()
	if e != nil || state.Stat.Mode != 0040755 || len(state.Security.Properties.RawSecurity.ACL.Entries) != 1 || state.Security.Properties.RawSecurity.OwnerUUID != [16]byte{4} {
		t.Fatal(state, e)
	}
	p.options.Captured.Creation.ParentACL.Entries = make([]appledouble.ACLEntry, 129)
	if e = p.createCapturedDestination(0100000); !errors.Is(e, appledouble.ErrACLInheritance) {
		t.Fatal(e)
	}
	// Failed inheritance cannot replace the previously created logical object.
	state, _, e = p.options.Captured.Destination.LogicalSnapshot()
	if e != nil || state.Stat.Mode&0777 != 0755 {
		t.Fatal(state, e)
	}
}

func TestAppleDoublePathResetAndRunFailureBoundaries(t *testing.T) {
	marker := errors.New("identity lookup refused")
	p := pathQualification(t)
	if _, e := p.RealUserUUID(); e != nil {
		t.Fatal(e)
	}
	p.native.identities = func(context.Context) (*appledouble.ACLIdentityCapture, error) { return nil, marker }
	if _, e := p.RealUserUUID(); !errors.Is(e, marker) {
		t.Fatal(e)
	}
	if _, e := p.Open(p.ctx, 4); e != nil {
		t.Fatal(e)
	}
	steps := p.ResetSecurity()
	if !errors.Is(steps[len(steps)-1].Err, marker) {
		t.Fatal(steps)
	}
	p.native.identities = func(context.Context) (*appledouble.ACLIdentityCapture, error) {
		return appledouble.NewACLIdentityCapture(func(appledouble.ACLIdentity) ([16]byte, error) { return [16]byte{}, marker }, nil), nil
	}
	steps = p.ResetSecurity()
	if !errors.Is(steps[len(steps)-1].Err, marker) {
		t.Fatal(steps)
	}
	p.options.Operation = PathUnpackAppleDouble
	p.options.Unpack.Stat = true
	p.source.meta = objectFailedStat{p.source.meta, marker}
	steps = p.ResetSecurity()
	if !errors.Is(steps[len(steps)-1].Err, ErrPathLifecycleUndefined) {
		t.Fatal(steps)
	}
	if e := p.sourceFile.Close(); e != nil {
		t.Fatal(e)
	}
	result, _ := p.Run(p.ctx)
	if result.Code != -1 || !errors.Is(result.Err, closedPathStatCause(t)) {
		t.Fatal(result)
	}
	p.sourceFile = nil
	if e := p.RemoveSource(); e != nil {
		t.Fatal(e)
	}
}

type pathSecurityWriteFailure struct {
	objectMetadata
	write, chmod error
	modes        []uint16
}

func (m *pathSecurityWriteFailure) WriteSecurity(aclmeta.DarwinChmodArguments) error { return m.write }
func (m *pathSecurityWriteFailure) Chmod(mode uint16) error {
	m.modes = append(m.modes, mode)
	return m.chmod
}

func TestAppleDoublePathTemporaryHandleQualification(t *testing.T) {
	marker := errors.New("saved destination effect failed")
	closedStat := closedPathStatCause(t)
	for _, tc := range []struct {
		name   string
		change func(*appleDoublePath)
		want   error
	}{
		{"open", func(p *appleDoublePath) {
			p.access.open = func(string, int, uint32, bool, bool, int) (*os.File, error) { return nil, marker }
		}, marker},
		{"stat", func(p *appleDoublePath) {
			old := p.access.open
			p.access.open = func(n string, f int, m uint32, a, b bool, c int) (*os.File, error) {
				v, e := old(n, f, m, a, b, c)
				if e == nil {
					if e = v.Close(); e != nil {
						t.Fatal(e)
					}
				}
				return v, e
			}
		}, closedStat},
		{"substituted", func(p *appleDoublePath) {
			old := p.access.open
			p.access.open = func(_ string, f int, m uint32, a, b bool, c int) (*os.File, error) {
				return old(p.sourceName, f, m, a, b, c)
			}
		}, ErrMetadataIdentity},
		{"metadata-bind", func(p *appleDoublePath) {
			p.native.heldMeta = func(*os.File) (objectMetadata, error) { return nil, marker }
		}, marker},
		{"write", func(p *appleDoublePath) {
			p.native.heldMeta = func(*os.File) (objectMetadata, error) {
				return &pathSecurityWriteFailure{objectMetadata: objectFixture(t).meta, write: marker}, nil
			}
		}, marker},
		{"mode-fallback", func(p *appleDoublePath) {
			p.native.heldMeta = func(*os.File) (objectMetadata, error) {
				return &pathSecurityWriteFailure{objectMetadata: objectFixture(t).meta, write: syscall.ENOTSUP}, nil
			}
		}, nil},
		{"fallback-failed", func(p *appleDoublePath) {
			p.native.heldMeta = func(*os.File) (objectMetadata, error) {
				return &pathSecurityWriteFailure{objectMetadata: objectFixture(t).meta, write: errors.ErrUnsupported, chmod: marker}, nil
			}
		}, marker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pathQualification(t)
			state, e := p.CaptureDestination()
			if e != nil {
				t.Fatal(e)
			}
			prepared, e := PreparePathSecurity(state.Properties, [16]byte{})
			if e != nil {
				t.Fatal(e)
			}
			tc.change(p)
			e = p.ApplyTemporarySecurity(prepared)
			if !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
			for _, s := range p.Close() {
				if s.Err != nil && tc.name != "stat" {
					t.Fatal(s)
				}
			}
		})
	}
	p := pathQualification(t)
	if e := p.ApplyTemporarySecurity(aclmeta.DarwinChmodProperties{RemoveACL: true, RawSecurity: &appledouble.FileSecurity{}}); e == nil {
		t.Fatal("invalid chmod accepted")
	}
	p.options.Captured = pathCapturedFixture(t, objectFixture(t), nil)
	if e := p.ApplyTemporarySecurity(aclmeta.DarwinChmodProperties{}); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	for _, mode := range []os.FileMode{os.ModeDir, os.ModeSymlink, os.ModeNamedPipe, 0600} {
		if got := pathModeType(mode); (mode == os.ModeDir && got != 0040000) || (mode == os.ModeSymlink && got != 0120000) || (mode == os.ModeNamedPipe && got != 0) || (mode == 0600 && got != 0100000) {
			t.Fatal(mode, got)
		}
	}
}

func TestAppleDoublePathValidatesSavedDestination(t *testing.T) {
	closedStat := closedPathStatCause(t)
	for _, fault := range []string{"none", "closed-original", "closed-payload", "substitution"} {
		t.Run(fault, func(t *testing.T) {
			p := pathQualification(t)
			state, e := p.CaptureDestination()
			if e != nil {
				t.Fatal(e)
			}
			if e = p.ApplyTemporarySecurity(state.Properties); e != nil {
				t.Fatal(e)
			}
			name := p.destinationName
			if fault == "substitution" {
				name = p.sourceName
			}
			p.destinationFile, e = os.Open(name)
			if e != nil {
				t.Fatal(e)
			}
			if fault == "closed-original" {
				if e = p.temporaryFile.Close(); e != nil {
					t.Fatal(e)
				}
			}
			if fault == "closed-payload" {
				if e = p.destinationFile.Close(); e != nil {
					t.Fatal(e)
				}
			}
			e = p.ValidateDestination()
			switch fault {
			case "none":
				if e != nil {
					t.Fatal(e)
				}
			case "substitution":
				if !errors.Is(e, ErrMetadataIdentity) || !errors.Is(e, syscall.EBADF) {
					t.Fatal(e)
				}
			default:
				if !errors.Is(e, closedStat) {
					t.Fatal(e)
				}
			}
			steps := p.Close()
			for _, s := range steps {
				if s.Err != nil && fault != "closed-original" && fault != "closed-payload" {
					t.Fatal(s)
				}
			}
		})
	}
}

func TestAppleDoublePathCallbackCancellationPreservesPartialWork(t *testing.T) {
	p := pathQualification(t)
	source := objectFixture(t, objectAttr("user.first", "first value"), objectAttr("user.second", "second value"))
	p.options.Captured = pathCapturedFixture(t, source, objectFixture(t))
	packed, e := CopyAppleDoublePath(p.ctx, p.sourceName, p.destinationName, p.options)
	if e != nil || !packed.Lifecycle.Completed {
		t.Fatal(packed, e)
	}
	packedObject := p.options.Captured.Destination
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	p.sourceName, p.destinationName = p.destinationName, p.sourceName
	p.options.Operation = PathUnpackAppleDouble
	p.options.Captured = pathCapturedFixture(t, packedObject, objectFixture(t))
	var notices []UnpackNotice
	p.options.Unpack.Callback = func(n UnpackNotice) CopyPipelineAction {
		notices = append(notices, n)
		if n.Stage == UnpackOrdinary && n.Event == XattrRestoreFinish {
			cancel()
		}
		return CopyPipelineContinue
	}
	result, e := CopyAppleDoublePath(ctx, p.sourceName, p.destinationName, p.options)
	if !errors.Is(e, context.Canceled) || result.Lifecycle.Completed || result.Lifecycle.Code != -1 || len(notices) < 2 {
		t.Fatal(result, e, notices)
	}
	_, attrs, e := p.options.Captured.Destination.LogicalSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	if len(attrs) != 1 || attrs[0].Name != notices[len(notices)-1].Name {
		t.Fatal("partial write was lost or later write happened", attrs, notices)
	}
	var closed []string
	for _, s := range result.Lifecycle.Steps {
		if s.Operation == "close-source" || s.Operation == "close-destination" {
			closed = append(closed, s.Operation)
			if s.Err != nil {
				t.Fatal(s)
			}
		}
	}
	if len(closed) != 2 {
		t.Fatal("cancellation omitted close", closed)
	}
	for _, name := range []string{p.sourceName, p.destinationName} {
		if e = os.Remove(name); e != nil {
			t.Fatal(e)
		}
	}
}

func TestAppleDoublePathRejectsUnknownProcessAndKind(t *testing.T) {
	p := pathQualification(t)
	p.options.Captured = pathCapturedFixture(t, objectFixture(t), objectFixture(t))
	p.options.Captured.RealUserUUID = nil
	if _, e := CopyAppleDoublePath(p.ctx, p.sourceName, p.destinationName, p.options); !errors.Is(e, appledouble.ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
	if _, e := p.RealUserUUID(); !errors.Is(e, appledouble.ErrACLIdentityUncaptured) {
		t.Fatal(e)
	}
	p.source, p.destination = p.options.Captured.Source, p.options.Captured.Destination
	p.options.Captured.EffectiveUserUUID = nil
	steps := p.ResetSecurity()
	if !errors.Is(steps[len(steps)-1].Err, appledouble.ErrACLIdentityUncaptured) {
		t.Fatal(steps)
	}
	p.options.Captured = nil
	capture := p.native.capture
	p.native.capture = func(n string, b bool) (PathMetadata, error) {
		v, e := capture(n, b)
		v.State.Stat.Mode = 0040755
		return v, e
	}
	if _, e := p.Open(p.ctx, 4); !errors.Is(e, ErrMetadataIdentity) {
		t.Fatal(e)
	}
	if p.sourceFile != nil || p.destinationFile != nil {
		t.Fatal("opened payload despite contradictory captured kind")
	}
}

func TestAppleDoublePathCapturedSymlinkCreationMode(t *testing.T) {
	for _, mask := range []uint16{0, 0022, 0077} {
		t.Run(fmt.Sprintf("%04o", mask), func(t *testing.T) {
			p := pathQualification(t)
			p.options.Captured = pathCapturedFixture(t, objectFixture(t), nil)
			p.options.Captured.Creation.Umask = mask
			p.sourceMetadata.State.Stat.Mode = 0120400
			if e := p.createCapturedDestination(0120000); e != nil {
				t.Fatal(e)
			}
			state, _, e := p.options.Captured.Destination.LogicalSnapshot()
			if e != nil || state.Stat.Mode != uint32(0120777&^mask) {
				t.Fatal(state, e)
			}
		})
	}
}

func TestAppleDoublePathCapturedIdentityUsesOneProvider(t *testing.T) {
	p := pathQualification(t)
	p.options.Captured = pathCapturedFixture(t, objectFixture(t), objectFixture(t))
	// These explicit provider observations differ from the local Unix stat and
	// reproduce a foreign platform binding without assuming Unix FileInfo.Sys.
	observed := LinkIdentity{Device: 987, Inode: 654}
	calls := 0
	p.native.identity = func(os.FileInfo) (LinkIdentity, bool) { calls++; return observed, true }
	if _, err := p.Open(p.ctx, 4); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || p.sourceMetadata.Identity != observed {
		t.Fatal("capture and held validation used different identity providers", calls, p.sourceMetadata.Identity)
	}
}

func TestAppleDoublePathResetCompletesAfterCancellation(t *testing.T) {
	p := pathQualification(t)
	p.source, p.destination = objectFixture(t), objectFixture(t)
	original := appledouble.ACLEntry{Principal: [16]byte{8}, Flags: 1, Rights: 2}
	temporary := appledouble.ACLEntry{Principal: [16]byte{7}, Flags: 1, Rights: TemporaryWriteRights}
	metadata := p.destination.meta.(*LogicalMetadata)
	if err := metadata.SetACL(&appledouble.ACL{Entries: []appledouble.ACLEntry{temporary, original}}); err != nil {
		t.Fatal(err)
	}
	type contextKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "cleanup identity context"))
	p.ctx = ctx
	cancel()
	p.native.identities = func(cleanup context.Context) (*appledouble.ACLIdentityCapture, error) {
		if cleanup.Value(contextKey{}) != "cleanup identity context" {
			t.Fatal("cleanup discarded caller context values")
		}
		if err := cleanup.Err(); err != nil {
			return nil, err
		}
		return appledouble.NewACLIdentityCapture(func(appledouble.ACLIdentity) ([16]byte, error) {
			return [16]byte{7}, cleanup.Err()
		}, nil), nil
	}
	for _, step := range p.ResetSecurity() {
		if step.Err != nil {
			t.Fatalf("cleanup %s failed after cancellation: %v", step.Operation, step.Err)
		}
	}
	acl, err := metadata.CaptureDestinationACL()
	if err != nil || acl == nil || len(acl.Entries) != 1 || acl.Entries[0] != original {
		t.Fatalf("temporary ACE survived cancellation: %+v, %v", acl, err)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("cleanup changed the caller's cancellation state")
	}
}
