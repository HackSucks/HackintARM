//go:build darwin

package hostdata

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/pathnative"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	sandbox "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/sandbox"
	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestAppleDoublePathNativeReplay(t *testing.T) {
	sandboxed, err := sandbox.CaptureAppSandbox()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "path-copyfile")
	if out, err := cirunner.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "../../testdata/appledouble/native/path-copyfile.c", "-o", helper).CombinedOutput(); err != nil {
		t.Fatalf("compile independent installed-copyfile oracle: %v: %s", err, out)
	}
	f, err := os.Open("../../testdata/appledouble/native/path-copyfile.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var fixture pathnative.Fixture
	if err = json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	cases := pathnative.Cases()
	if len(cases) != len(fixture.Cases) {
		t.Fatal("native cases changed")
	}
	for i, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%03d", i), func(t *testing.T) {
			spec := c
			spec.Native = pathnative.Observation{}
			if !reflect.DeepEqual(spec, cases[i]) {
				t.Fatal("native input changed")
			}
			src, dst, target := prepareNativePathCase(t, c)
			// The recorded baseline is bound to its input context. Ambient native
			// attributes (including protected provenance) must not be filtered or
			// assumed equal on another process/host. Qualify current behavior with
			// independent C and Go operations on verified equivalent inputs.
			nativeSource, nativeDestination, nativeTarget := prepareNativePathCase(t, c)
			mask := -1
			if c.SetUmask {
				mask = c.Umask
			}
			out, err := cirunner.Command(helper, nativeSource, nativeDestination, nativeTarget, strconv.Itoa(c.Route), strconv.Itoa(c.Selected), strconv.Itoa(c.Quit), strconv.Itoa(c.SourceMode), strconv.Itoa(mask)).CombinedOutput()
			if err != nil {
				t.Fatalf("installed-copyfile oracle: %v: %s", err, out)
			}
			if err := json.Unmarshal(out, &c.Native); err != nil {
				t.Fatalf("native observation: %v: %s", err, out)
			}
			// Unmarshal overwrites fields present in C output; the digest is
			// computed here and must never retain a previous host's value.
			c.Native.DestinationSHA256 = ""
			if st, err := os.Lstat(nativeDestination); err == nil && st.Mode().IsRegular() {
				data, err := os.ReadFile(nativeDestination)
				if err != nil {
					t.Fatal(err)
				}
				c.Native.DestinationSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
			}
			out, err = cirunner.Command(helper, "--inspect", src, dst, target).CombinedOutput()
			if err != nil {
				t.Fatalf("independent input inspection: %v: %s", err, out)
			}
			var input pathnative.InputContext
			if err := json.Unmarshal(out, &input); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(input.WithoutObjectIdentity(), c.Native.Input.WithoutObjectIdentity()) {
				t.Fatalf("C and Go input attributes differ: Go=%+v C=%+v", input, c.Native.Input)
			}
			if input.Sandboxed != sandboxed {
				t.Fatalf("oracle process sandbox=%t differs from Go process=%t", input.Sandboxed, sandboxed)
			}
			options := AppleDoublePathOptions{Operation: PathPackAppleDouble, Pack: DefaultObjectPackOptions(), Unpack: DefaultObjectUnpackOptions(), MaxOpenAttempts: 8, Exclusive: c.Selected&2 != 0, NoFollowSource: c.Selected&4 != 0, NoFollowDestination: c.Selected&4 != 0, UnlinkDestination: c.Selected&8 != 0, MoveSource: c.Selected&16 != 0}
			options.Pack.Stat = c.Selected&1 != 0
			options.Unpack.Stat = c.Selected&1 != 0
			options.Pack.CopyACL = c.Selected&32 != 0
			if c.Route == 1 {
				options.Operation = PathUnpackAppleDouble
			}
			var notices []pathnative.Notice
			if c.Selected&64 != 0 || c.Quit != 0 {
				action := CopyPipelineContinue
				if c.Quit != 0 {
					action = CopyPipelineQuit
				}
				options.Pack.Callback = func(n PackNotice) CopyPipelineAction {
					stage := map[PackEvent]int{PackStart: 1, PackFinish: 2, PackError: 3, PackProgress: 4}[n.Event]
					notices = append(notices, pathnative.Notice{What: 5, Stage: stage, Copied: int64(n.Copied)})
					return action
				}
				options.Unpack.Callback = func(n UnpackNotice) CopyPipelineAction {
					stage := map[XattrRestoreEvent]int{XattrRestoreStart: 1, XattrRestoreFinish: 2, XattrRestoreError: 3}[n.Event]
					notices = append(notices, pathnative.Notice{What: 5, Stage: stage, Copied: int64(n.Copied)})
					return action
				}
			}
			before := nativePathSnapshot(t, dst)
			if before != c.Native.Before {
				t.Fatalf("setup got%+v want%+v", before, c.Native.Before)
			}
			if c.SetUmask {
				prior := unix.Umask(c.Umask)
				defer unix.Umask(prior)
			}
			result, operationErr := CopyAppleDoublePath(context.Background(), src, dst, options)
			out, err = cirunner.Command(helper, "--inspect", src, dst, target).CombinedOutput()
			if err != nil {
				t.Fatalf("independent output inspection: %v: %s", err, out)
			}
			var output pathnative.InputContext
			if err := json.Unmarshal(out, &output); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(output.WithoutObjectIdentity(), c.Native.Output.WithoutObjectIdentity()) {
				t.Errorf("C and Go output context differs: Go=%+v C=%+v", output, c.Native.Output)
			}
			if result.Lifecycle.Code != c.Native.Code {
				t.Errorf("code got%d want%d: %v", result.Lifecycle.Code, c.Native.Code, operationErr)
			}
			if c.Native.Code < 0 && operationErr == nil {
				t.Error("native failure lost")
			}
			for _, pair := range []struct {
				name, path string
				want       pathnative.Snapshot
			}{{"destination", dst, c.Native.After}, {"source", src, c.Native.Source}, {"target", target, c.Native.Target}} {
				if got := nativePathSnapshot(t, pair.path); got != pair.want {
					t.Errorf("%s got%+v want%+v: %v", pair.name, got, pair.want, operationErr)
				}
			}
			if len(notices) != len(c.Native.Notices) || len(notices) > 0 && !reflect.DeepEqual(notices, c.Native.Notices) {
				t.Errorf("notices got%+v want%+v", notices, c.Native.Notices)
			}
			if c.Native.DestinationSHA256 != "" {
				data, err := os.ReadFile(dst)
				if err != nil {
					t.Fatal(err)
				}
				if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != c.Native.DestinationSHA256 {
					t.Errorf("destination bytes got%s want%s", got, c.Native.DestinationSHA256)
				}
			}
		})
	}
}

func prepareNativePathCase(t *testing.T, c pathnative.Case) (src, dst, target string) {
	t.Helper()
	root := t.TempDir()
	src, dst, target = filepath.Join(root, "source"), filepath.Join(root, "destination"), filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("TARGET"), 0440); err != nil {
		t.Fatal(err)
	}
	data := []byte("SOURCE")
	if c.Route == 1 {
		var err error
		data, err = (&appledouble.File{Attrs: []appledouble.Attr{{Name: "com.example.path", Value: []byte("source")}}}).Encode()
		if err != nil {
			t.Fatal(err)
		}
	}
	kind := c.SourceKind
	if c.Route == 1 && kind == 1 {
		data = data[:len(data)-1]
		kind = 0
	} else if c.Route == 1 && kind > 1 {
		kind--
	}
	var err error
	switch kind {
	case 0:
		err = os.WriteFile(src, data, 0440)
	case 1:
		err = os.Mkdir(src, 0550)
	case 2:
		err = os.WriteFile(filepath.Join(root, "source-target"), data, 0440)
		if err == nil {
			err = os.Symlink("source-target", src)
		}
	case 3:
		err = os.Symlink("missing-source", src)
	}
	if err != nil {
		t.Fatal(err)
	}
	switch c.DestinationKind {
	case 1:
		err = os.WriteFile(dst, []byte("DESTINATION"), 0400)
	case 2:
		err = os.Mkdir(dst, 0500)
	case 3:
		err = os.Symlink("target", dst)
	case 4:
		err = os.Symlink("missing-destination", dst)
	}
	if err != nil {
		t.Fatal(err)
	}
	if c.Selected&32 != 0 && c.DestinationKind != 0 {
		fd, err := unix.Open(dst, unix.O_RDONLY|unix.O_SYMLINK, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), dst)
		h, err := NewHeldMetadata(f)
		if err == nil {
			err = h.SetACL(&appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 2}}})
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
	}
	if c.Route == 0 && !c.NullSource {
		fd, err := unix.Open(src, unix.O_RDONLY|unix.O_SYMLINK, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), src)
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		if err = unix.Fchmod(fd, uint32(st.Mode)|0200); err != nil {
			t.Fatal(err)
		}
		if err = SetXattr(f, "com.example.path", []byte("source")); err != nil {
			t.Fatal(err)
		}
		if err = unix.Fchmod(fd, uint32(st.Mode)); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if c.SourceMode != 0 {
		fd, err := unix.Open(src, unix.O_RDONLY|unix.O_SYMLINK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = unix.Fchmod(fd, uint32(c.SourceMode)); err != nil {
			_ = unix.Close(fd)
			t.Fatal(err)
		}
		if err = unix.Close(fd); err != nil {
			t.Fatal(err)
		}
	}
	if c.NullSource {
		src = os.DevNull
	}
	return src, dst, target
}

func nativePathSnapshot(t *testing.T, path string) pathnative.Snapshot {
	t.Helper()
	m, err := CapturePathMetadata(path, true)
	if err != nil {
		var eno syscall.Errno
		if errors.As(err, &eno) {
			return pathnative.Snapshot{Errno: int(eno)}
		}
		t.Fatal(err)
	}
	s := pathnative.Snapshot{Exists: true, Mode: m.State.Stat.Mode, Size: m.Size, ACLCount: -1}
	if s.Mode&0170000 == 0040000 {
		s.Size = 0
	}
	if raw := m.State.Security.Properties.RawSecurity; raw != nil && raw.ACL != nil {
		s.ACLCount = len(raw.ACL.Entries)
	}
	data, present, err := ReadXattrNoFollow(path, "com.example.path", 128)
	if err != nil {
		var eno syscall.Errno
		if !errors.As(err, &eno) {
			t.Fatal(err)
		}
		s.XattrErrno = int(eno)
	} else if !present {
		s.XattrErrno = 93
	} else {
		s.XattrHex = hex.EncodeToString(data)
	}
	return s
}
