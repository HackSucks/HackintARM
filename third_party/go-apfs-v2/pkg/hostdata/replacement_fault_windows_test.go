package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

func TestReplacementWindowsHeldStreams(t *testing.T) {
	for _, kind := range []string{"ordinary", "compressed", "sparse"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source")
			source, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if _, err = source.WriteString("old main data must be excluded"); err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("x"), (8<<20)+1)
			if err = os.WriteFile(path+":metadata", payload, 0600); err != nil {
				t.Fatal(err)
			}
			strictWindowsSet(t, path, "replacement.test", []byte("native EA"))
			if kind == "compressed" {
				replacementCompress(t, path)
			}
			if kind == "sparse" {
				if err = replacementSparse(source); err != nil {
					t.Fatal(err)
				}
				named, e := os.OpenFile(path+":sparse", os.O_CREATE|os.O_RDWR, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if e = replacementSparse(named); e != nil {
					t.Fatal(e)
				}
				const position = int64(4<<30) + 23
				_, e = named.WriteAt([]byte("tail"), position)
				if e = errors.Join(e, named.Close()); e != nil {
					t.Fatal(e)
				}
			}
			info, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			_, stage, parent := replacementTestStage(t)
			target, err := prepareReplacementStreamsAtContext(t.Context(), source, stage, info)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if info, e := target.Stat(); e != nil || info.Size() != 0 {
				t.Fatalf("main data retained: %v %v", info, e)
			}
			if err = restoreReplacementMetadataAtContext(t.Context(), source, target, info); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(parent, "private", "replacement") + ":metadata")
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("ADS drift: %v", err)
			}
			value, present, err := ReadXattr(target, "replacement.test", 128)
			if err != nil || !present || string(value) != "native EA" {
				t.Fatalf("EA drift: %q %v %v", value, present, err)
			}
			actual, e := replacementBasic(target)
			if e != nil {
				t.Fatal(e)
			}
			original, e := replacementBasic(source)
			if e != nil {
				t.Fatal(e)
			}
			if actual.Attributes != original.Attributes {
				t.Fatalf("attributes=%#x want %#x", actual.Attributes, original.Attributes)
			}
			if kind == "sparse" {
				named, e := os.Open(filepath.Join(parent, "private", "replacement") + ":sparse")
				if e != nil {
					t.Fatal(e)
				}
				var tail [4]byte
				_, e = named.ReadAt(tail[:], int64(4<<30)+23)
				if e = errors.Join(e, named.Close()); e != nil || string(tail[:]) != "tail" {
					t.Fatalf("large sparse ADS: %q %v", tail, e)
				}
			}
		})
	}
	t.Run("compressed cancellation checkpoints", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "source")
		if err := os.WriteFile(path, []byte("original main payload"), 0600); err != nil {
			t.Fatal(err)
		}
		stream := bytes.Repeat([]byte("metadata"), 8193)
		if err := os.WriteFile(path+":metadata", stream, 0600); err != nil {
			t.Fatal(err)
		}
		replacementCompress(t, path)
		source, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		info, err := source.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = source.Seek(7, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		checkpoints := 0
		for stop := 0; stop <= checkpoints; stop++ {
			t.Run(fmt.Sprintf("stop-%d", stop), func(t *testing.T) {
				_, stage, parent := replacementTestStage(t)
				base, cancel := context.WithCancel(t.Context())
				defer cancel()
				ctx := &replacementCheckpointContext{Context: base, cancel: cancel, stop: stop}
				file, operationErr := prepareReplacementStreamsAtContext(ctx, source, stage, info)
				if stop == 0 {
					if operationErr != nil || file == nil {
						t.Fatalf("compressed backup control: %v", operationErr)
					}
					defer file.Close()
					checkpoints = ctx.calls
					basic, e := replacementBasic(file)
					if e != nil || basic.Attributes&windows.FILE_ATTRIBUTE_COMPRESSED == 0 {
						t.Fatalf("compression lost: %#x %v", basic.Attributes, e)
					}
					got, e := os.ReadFile(filepath.Join(parent, "private", "replacement") + ":metadata")
					if e != nil || !bytes.Equal(got, stream) {
						t.Fatalf("compressed backup ADS: %d bytes %v", len(got), e)
					}
					if e = file.Close(); e != nil {
						t.Fatal(e)
					}
				} else if !errors.Is(operationErr, context.Canceled) || file != nil {
					t.Fatalf("checkpoint %d/%d returned file=%v error=%v", stop, checkpoints, file, operationErr)
				}
				// Removal is also a native handle-leak proof after partial BackupWrite.
				if e := stage.Remove("replacement"); e != nil && !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("canceled backup retained target capability: %v", e)
				}
				if position, e := source.Seek(0, io.SeekCurrent); e != nil || position != 7 {
					t.Fatalf("borrowed source position changed: %d %v", position, e)
				}
			})
		}
	})

}

func TestReplacementWindowsBackupAdapterFailures(t *testing.T) {
	fault := errors.New("native backup failure")
	for _, tc := range []struct {
		name string
		n    uint32
		err  error
		want error
	}{
		{"read-failure", 0, fault, fault}, {"overlong", 3, nil, nil}, {"read-eof", 0, nil, io.EOF}, {"short-write", 1, nil, io.ErrShortWrite}, {"complete", 2, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &replacementBackup{call: func(_ *os.File, _ []byte, _ bool, state *uintptr) (uint32, error) { *state = 1; return tc.n, tc.err }}
			buffer := make([]byte, 2)
			var err error
			if tc.name == "short-write" || tc.name == "complete" {
				_, err = adapter.Write(buffer)
			} else {
				_, err = adapter.Read(buffer)
			}
			if tc.name == "overlong" {
				if err == nil {
					t.Fatal("accepted native overrun")
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			adapter.call = func(_ *os.File, _ []byte, abort bool, _ *uintptr) (uint32, error) {
				if !abort {
					t.Fatal("cleanup did not abort")
				}
				return 0, fault
			}
			if err = adapter.close(); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			adapter.state = 0
			if err = adapter.close(); err != nil {
				t.Fatal(err)
			}
			if n, err := adapter.Read(nil); n != 0 || err != nil {
				t.Fatal(n, err)
			}
			if n, err := adapter.Write(nil); n != 0 || err != nil {
				t.Fatal(n, err)
			}
		})
	}
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	adapter := &replacementBackup{file: source, call: replacementBackupRead}
	if _, err = adapter.Read(make([]byte, 20)); err == nil {
		t.Fatal("accepted closed native source")
	}
}

func TestReplacementWindowsMissingAndCloseFailure(t *testing.T) {
	missing := windows.NTStatus(0xc0000034)
	closeErr := errors.New("private metadata directory close failed")
	for _, tc := range []struct {
		name   string
		input  error
		failed bool
	}{
		{"missing", missing, false},
		{"single joined missing", errors.Join(missing), false},
		{"missing plus close", errors.Join(missing, closeErr), true},
		{"nested missing plus close", errors.Join(errors.Join(missing), closeErr), true},
		{"close alone", closeErr, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normalized := replacementWindowsError(tc.input)
			got := cleanupReplacement(func() error { return normalized })
			if tc.failed {
				if !errors.Is(got, closeErr) {
					t.Fatalf("lost cleanup failure: %v", got)
				}
			} else if got != nil {
				t.Fatal(got)
			}
			if errors.Is(tc.input, missing) && !errors.Is(normalized, os.ErrNotExist) {
				t.Fatalf("missing native cause not normalized: %v", normalized)
			}
		})
	}
	if replacementWindowsError(nil) != nil {
		t.Fatal("nil changed")
	}
}

func TestReplacementWindowsSecurityDescriptorFidelity(t *testing.T) {
	for _, descriptor := range []string{
		"D:P(A;;FA;;;WD)", "D:(A;ID;FA;;;WD)", "D:AI(A;ID;FA;;;WD)", "D:P", "D:NO_ACCESS_CONTROL",
	} {
		t.Run(descriptor, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "security")
			name, err := windows.UTF16PtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(handle), path)
			original, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if e := replacementSetFileSecurity(file, windows.DACL_SECURITY_INFORMATION, original); e != nil {
					t.Error(e)
				}
				if e := file.Close(); e != nil {
					t.Error(e)
				}
			}()
			wanted, err := windows.SecurityDescriptorFromString(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if err = replacementSetFileSecurity(file, windows.DACL_SECURITY_INFORMATION, wanted); err != nil {
				t.Fatal(err)
			}
			actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			if actual.String() != wanted.String() {
				t.Fatalf("full DACL fidelity: got %s want %s", actual.String(), wanted.String())
			}
		})
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if err = replacementSetFileSecurity(closed, windows.DACL_SECURITY_INFORMATION, sd); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestReplacementWindowsNativeFailures(t *testing.T) {
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	live, err := os.CreateTemp(t.TempDir(), "live")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	info, err := live.Stat()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name   string
		invoke func() error
	}{
		{"identity closed", func() error { _, e := replacementHeldIdentity(closed); return e }},
		{"final path closed", func() error { _, e := replacementFinalPath(t.Context(), closed); return e }},
		{"final path canceled", func() error { _, e := replacementFinalPath(canceled, live); return e }},
		{"duplicate invalid", func() error { _, e := duplicateReplacementHandle(windows.InvalidHandle, "invalid"); return e }},
		{"reopen closed", func() error { _, e := reopenReplacementFile(closed, windows.GENERIC_READ); return e }},
		{"private acl closed", func() error { return replacementPrivateFileAccess(closed) }},
		{"readonly closed", func() error { return replacementClearReadonly(t.Context(), closed) }},
		{"cleanup capability closed", func() error { _, e := replacementCleanupCapability(closed); return e }},
		{"metadata closed root", func() error { _, e := openReplacementStageMetadata(root); return e }},
		{"anchor closed root", func() error { _, e := replacementStageAnchor(root); return e }},
		{"private parent closed", func() error { _, e := makeReplacementDirectoryAt(t.Context(), root, "private"); return e }},
		{"private canceled", func() error { _, e := makeReplacementDirectoryAt(canceled, root, "private"); return e }},
		{"restore source closed", func() error { return restoreReplacementMetadataContext(t.Context(), closed, live, info) }},
		{"restore target closed", func() error { return restoreReplacementMetadataContext(t.Context(), live, closed, info) }},
		{"restore canceled", func() error { return restoreReplacementMetadataContext(canceled, live, live, info) }},
		{"restore rooted canceled", func() error { return restoreReplacementMetadataAtContext(canceled, live, live, info) }},
		{"restore rooted closed", func() error { return restoreReplacementMetadataAtContext(t.Context(), closed, live, info) }},
		{"compression closed", func() error { return copyReplacementCompression(t.Context(), closed, live) }},
		{"streams closed", func() error { return copyReplacementStreamsContext(t.Context(), closed, live) }},
		{"prepare streams canceled", func() error { _, e := prepareReplacementStreamsAtContext(canceled, live, root, info); return e }},
		{"prepare streams source closed", func() error { _, e := prepareReplacementStreamsAtContext(t.Context(), closed, root, info); return e }},
		{"prepare streams root closed", func() error { _, e := prepareReplacementStreamsAtContext(t.Context(), live, root, info); return e }},
		{"prepare native source closed", func() error { _, e := prepareReplacementAtContext(t.Context(), closed, root, info); return e }},
		{"efs pin canceled", func() error { _, e := replacementPinEFS(canceled, live); return e }},
		{"efs pin closed", func() error { _, e := replacementPinEFS(t.Context(), closed); return e }},
		{"efs verify closed", func() error { return replacementVerifyEFS(t.Context(), closed, live) }},
		{"efs query canceled", func() error { _, e := replacementQueryEFS(canceled, live.Name(), replacementQueryUsers); return e }},
		{"efs query invalid name", func() error { _, e := replacementQueryEFS(t.Context(), "bad\x00name", replacementQueryUsers); return e }},
		{"efs query absent", func() error {
			_, e := replacementQueryEFS(t.Context(), filepath.Join(t.TempDir(), "absent"), replacementQueryUsers)
			return e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := tc.invoke(); e == nil {
				t.Fatal("native failure accepted")
			}
		})
	}
	t.Run("copy closed root", func(t *testing.T) {
		file, e := copyReplacementWindows(t.Context(), live, root, runReplacementCopy)
		if e == nil || file != nil {
			t.Fatalf("closed stage admitted copy: %v %v", file, e)
		}
	})
	t.Run("copy closed source", func(t *testing.T) {
		_, stage, _ := replacementTestStage(t)
		file, e := copyReplacementWindows(t.Context(), closed, stage, runReplacementCopy)
		if e == nil || file != nil {
			t.Fatalf("closed source admitted copy: %v %v", file, e)
		}
		if _, e = stage.Stat("anchor"); !errors.Is(e, os.ErrNotExist) {
			t.Fatalf("source admission failure retained anchor: %v", e)
		}
	})
	if replacementCopyProgress(0, 0, 0, 0) != 1 {
		t.Fatal("unknown callback capability accepted")
	}
	for _, initial := range []error{errors.New("earlier callback failure"), nil} {
		state := &replacementCopyState{ctx: canceled, err: initial}
		if state.progress(0, windows.InvalidHandle, windows.InvalidHandle) != 1 || state.err == nil {
			t.Fatal("canceled or failed callback continued")
		}
	}
	id, err := replacementHeldIdentity(live)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		source, target windows.Handle
		state          replacementCopyState
	}{
		{"invalid source", windows.InvalidHandle, windows.Handle(live.Fd()), replacementCopyState{ctx: t.Context()}},
		{"invalid destination", windows.Handle(live.Fd()), windows.InvalidHandle, replacementCopyState{ctx: t.Context(), source: id}},
		{"changed destination", windows.Handle(live.Fd()), windows.Handle(live.Fd()), replacementCopyState{ctx: t.Context(), source: id, validated: true}},
		{"closed stage", windows.Handle(live.Fd()), windows.Handle(live.Fd()), replacementCopyState{ctx: t.Context(), source: id, stage: root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.state.progress(0, tc.source, tc.target) != 1 || tc.state.err == nil {
				t.Fatal("invalid callback continued")
			}
		})
	}
	t.Run("callback metadata access denied", func(t *testing.T) {
		_, stage, parent := replacementTestStage(t)
		target, e := stage.OpenFile("replacement", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			t.Fatal(e)
		}
		defer target.Close()
		guard, e := reopenReplacementFile(target, windows.READ_CONTROL|windows.WRITE_DAC)
		if e != nil {
			t.Fatal(e)
		}
		defer guard.Close()
		// OWNER RIGHTS prevents the implicit owner WRITE_DAC grant. Keep an
		// existing authorized capability so the test can restore the private DACL.
		sd, e := windows.SecurityDescriptorFromString("D:P(D;;WD;;;S-1-3-4)(A;;FA;;;WD)")
		if e != nil {
			t.Fatal(e)
		}
		if e = replacementSetFileSecurity(guard, windows.DACL_SECURITY_INFORMATION, sd); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if e := replacementPrivateFileAccess(guard); e != nil && !errors.Is(e, os.ErrClosed) {
				t.Error(e)
			}
		}()
		denied, nativeErr := reopenReplacementFile(target, windows.WRITE_DAC)
		if denied != nil {
			_ = denied.Close()
		}
		if !errors.Is(nativeErr, windows.ERROR_ACCESS_DENIED) || denied != nil {
			t.Fatalf("native owner-rights control: file=%v error=%v", denied, nativeErr)
		}
		state := replacementCopyState{ctx: t.Context(), source: id, stage: stage, path: target.Name()}
		if state.progress(0, windows.Handle(live.Fd()), windows.Handle(target.Fd())) != 1 || !errors.Is(state.err, windows.ERROR_ACCESS_DENIED) || state.file != nil || state.security != nil || state.validated {
			t.Fatalf("denied metadata admission retained capability: %#v", state)
		}
		if e = replacementPrivateFileAccess(guard); e != nil {
			t.Fatal(e)
		}
		if e = errors.Join(guard.Close(), target.Close()); e != nil {
			t.Fatal(e)
		}
		pointer, e := windows.UTF16PtrFromString(filepath.Join(parent, "private", "replacement"))
		if e != nil {
			t.Fatal(e)
		}
		handle, e := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if e != nil {
			t.Fatalf("callback failure leaked duplicated native handle: %v", e)
		}
		if e = windows.CloseHandle(handle); e != nil {
			t.Fatal(e)
		}
	})

}

func TestReplacementWindowsEFSKeyValidation(t *testing.T) {
	world, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	value := byte(1)
	for _, tc := range []struct {
		name        string
		left, right replacementEFSHash
		equal       bool
	}{
		{"one missing SID", replacementEFSHash{SID: world, Hash: &replacementEFSBlob{}}, replacementEFSHash{Hash: &replacementEFSBlob{}}, false},
		{"different SID", replacementEFSHash{SID: world, Hash: &replacementEFSBlob{}}, replacementEFSHash{SID: system, Hash: &replacementEFSBlob{}}, false},
		{"same SID", replacementEFSHash{SID: world, Hash: &replacementEFSBlob{}}, replacementEFSHash{SID: world, Hash: &replacementEFSBlob{}}, true},
		{"different sizes", replacementEFSHash{Hash: &replacementEFSBlob{Size: 1, Data: &value}}, replacementEFSHash{Hash: &replacementEFSBlob{}}, false},
		{"missing bytes", replacementEFSHash{Hash: &replacementEFSBlob{Size: 1}}, replacementEFSHash{Hash: &replacementEFSBlob{Size: 1, Data: &value}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := replacementEFSKeyEqual(&tc.left, &tc.right); got != tc.equal {
				t.Fatal(got)
			}
		})
	}
}

func setReplacementTestInfo(r *Replacement, info os.FileInfo) { r.rooted.info = info }

func TestReplacementWindowsFinalPathProvider(t *testing.T) {
	for _, tc := range []struct {
		name, path    string
		first, second error
		limit         uint32
		wantError     bool
	}{
		{name: "GUID", path: `\\?\Volume{example}\held`},
		{name: "large buffer", path: `\\?\Volume{example}\` + strings.Repeat("segment\\", 100)},
		{name: "UNC missing GUID", path: `\\?\UNC\server\share\held`, first: windows.ERROR_PATH_NOT_FOUND},
		{name: "UNC unsupported GUID", path: `\\?\UNC\server\share\held`, first: windows.ERROR_INVALID_PARAMETER},
		{name: "mutable drive rejected", path: `C:\held`, first: windows.ERROR_PATH_NOT_FOUND, wantError: true},
		{name: "permission not retried", first: windows.ERROR_ACCESS_DENIED, wantError: true},
		{name: "both forms missing", first: windows.ERROR_PATH_NOT_FOUND, second: windows.ERROR_PATH_NOT_FOUND, wantError: true},
		{name: "namespace bound", limit: 32769, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			path, err := replacementResolveFinalPath(t.Context(), func(buffer []uint16, flags uint32) (uint32, error) {
				calls++
				if flags == 1 && tc.first != nil {
					return 0, tc.first
				}
				if flags == 0 && tc.second != nil {
					return 0, tc.second
				}
				if tc.limit != 0 {
					return tc.limit, nil
				}
				encoded, e := windows.UTF16FromString(tc.path)
				if e != nil {
					t.Fatal(e)
				}
				if len(encoded) > len(buffer) {
					return uint32(len(encoded)), nil
				}
				copy(buffer, encoded)
				return uint32(len(encoded) - 1), nil
			})
			if tc.wantError {
				if err == nil || path != "" {
					t.Fatal(path, err)
				}
			} else if err != nil || path != tc.path {
				t.Fatal(path, err)
			}
			if tc.name == "permission not retried" && calls != 1 {
				t.Fatalf("permission failure retried %d times", calls)
			}
			if tc.name == "large buffer" && calls != 2 {
				t.Fatalf("growth calls %d", calls)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	_, err := replacementResolveFinalPath(ctx, func([]uint16, uint32) (uint32, error) { calls++; cancel(); return 1024, nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
	_, err = replacementResolveFinalPath(ctx, func([]uint16, uint32) (uint32, error) { t.Fatal("query after cancellation"); return 0, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReplacementWindowsSecurityValidation(t *testing.T) {
	if e := replacementFileControl((*os.File)(nil), func(windows.Handle) error { t.Fatal("invalid file reached callback"); return nil }); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}

	file, err := os.CreateTemp(t.TempDir(), "security")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = replacementSetFileSecurity(file, windows.DACL_SECURITY_INFORMATION, &windows.SECURITY_DESCRIPTOR{}); err == nil {
		t.Fatal("invalid security revision accepted")
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := sd.ToAbsolute()
	if err != nil {
		t.Fatal(err)
	}
	if err = replacementSetFileSecurity(file, windows.DACL_SECURITY_INFORMATION, absolute); !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatal(err)
	}
	// The held read-only capability cannot modify the security descriptor even
	// when a separate owner handle has sufficient access to the same file.
	readOnly, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err = replacementSetFileSecurity(readOnly, windows.DACL_SECURITY_INFORMATION, sd); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal(err)
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed-control")
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err = replacementFileControl(closed, func(windows.Handle) error { t.Fatal("closed file reached native callback"); return nil }); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestReplacementWindowsEFSEveryCancellationCheckpoint(t *testing.T) {
	openHeld := func(name string) *os.File {
		pointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			t.Fatal(err)
		}
		h, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return os.NewFile(uintptr(h), name)
	}
	names := []string{filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "target")}
	for _, name := range names {
		if err := os.WriteFile(name, []byte("encrypted native data"), 0600); err != nil {
			t.Fatal(err)
		}
		replacementEncrypt(t, name)
	}
	source, target := openHeld(names[0]), openHeld(names[1])
	defer source.Close()
	defer target.Close()
	acquireDelete := func(t *testing.T, name string) windows.Handle {
		t.Helper()
		pointer, e := windows.UTF16PtrFromString(name)
		if e != nil {
			t.Fatal(e)
		}
		h, e := windows.CreateFile(pointer, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if e != nil {
			t.Fatalf("leaked no-delete-share pin: %v", e)
		}
		return h
	}
	for _, operation := range []string{"pin", "query", "verify", "prepare"} {
		t.Run(operation, func(t *testing.T) {
			checkpoints := 0
			for stop := 0; stop <= checkpoints; stop++ {
				ctx, cancel := context.WithCancel(t.Context())
				observed := &replacementCheckpointContext{Context: ctx, cancel: cancel, stop: stop}
				var err error
				switch operation {
				case "pin":
					var file *os.File
					file, err = replacementPinEFS(observed, source)
					if err != nil && file != nil {
						t.Fatal("failed acquisition returned owned pin")
					}
					if file != nil {
						err = errors.Join(err, file.Close())
					}
				case "query":
					var list *replacementEFSList
					list, err = replacementQueryEFS(observed, names[0], replacementQueryUsers)
					if err != nil && list != nil {
						t.Fatal("failed query returned owned list")
					}
					if list != nil {
						freeReplacementEFS(list)
					}
				case "verify":
					err = replacementVerifyEFS(observed, source, target)
				case "prepare":
					parent := t.TempDir()
					r, e := PrepareReplacementContext(observed, source, parent)
					err = e
					if e != nil && r != nil {
						t.Fatal("failed encrypted preparation returned stage")
					}
					if r != nil {
						err = errors.Join(err, r.Close())
					}
					entries, e := os.ReadDir(parent)
					if e != nil || len(entries) != 0 {
						t.Fatalf("encrypted cancellation leaked stage: %v %v", entries, e)
					}
				}
				cancel()
				if stop == 0 {
					if err != nil {
						t.Fatal(err)
					}
					checkpoints = observed.calls
				} else if !errors.Is(err, context.Canceled) {
					t.Fatalf("checkpoint %d/%d: %v", stop, checkpoints, err)
				}
				for _, name := range names {
					if e := windows.CloseHandle(acquireDelete(t, name)); e != nil {
						t.Fatal(e)
					}
				}
			}
			if checkpoints == 0 {
				t.Fatal("no native cancellation checkpoints")
			}
		})
	}
	plain, e := os.CreateTemp(t.TempDir(), "plain")
	if e != nil {
		t.Fatal(e)
	}
	defer plain.Close()
	if e = replacementVerifyEFS(t.Context(), source, plain); e == nil {
		t.Fatal("unencrypted replacement accepted")
	}
	if e = plain.Close(); e != nil {
		t.Fatal(e)
	}
	if e = replacementVerifyEFS(t.Context(), source, plain); e == nil {
		t.Fatal("closed encrypted replacement accepted")
	}
	for _, name := range names {
		held := acquireDelete(t, name)
		e = replacementVerifyEFS(t.Context(), source, target)
		closeErr := windows.CloseHandle(held)
		if !errors.Is(e, windows.ERROR_SHARING_VIOLATION) || closeErr != nil {
			t.Fatalf("required namespace pin not enforced: %v / %v", e, closeErr)
		}
	}
}

func TestReplacementWindowsPrivateFailures(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = root.Mkdir("exists", 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exists", "invalid\x00name"} {
		release, e := makeReplacementDirectoryAt(t.Context(), root, name)
		if release != nil {
			t.Error("failed private creation returned a guard")
			_ = release()
		}
		if e == nil {
			t.Fatalf("accepted %q", name)
		}
		if name == "exists" && !errors.Is(e, os.ErrExist) {
			t.Fatalf("private directory collision lost its Go error class: %v", e)
		}
	}
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// The NT creation path must expose the same error class as Go's native
	// directory operation. Downstream writers use it to preserve independent
	// sibling commits after an allocation denial.
	if err = root.Mkdir("denied", 0700); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(directory, "denied")
	if out, e := cirunner.Command("icacls", denied, "/deny", "*S-1-1-0:(AD,WD)").CombinedOutput(); e != nil {
		t.Fatalf("deny creation: %v: %s", e, out)
	}
	t.Cleanup(func() {
		if out, e := cirunner.Command("icacls", denied, "/remove:d", "*S-1-1-0").CombinedOutput(); e != nil {
			t.Errorf("restore creation: %v: %s", e, out)
		}
	})
	if e := os.Mkdir(filepath.Join(denied, "control"), 0700); !errors.Is(e, os.ErrPermission) {
		t.Fatalf("native directory denial control: %v", e)
	}
	for _, acquire := range []func() error{
		func() error {
			release, e := makeReplacementDirectoryAt(t.Context(), root, filepath.Join("denied", "private"))
			if release != nil {
				t.Error("denied creation returned a capability")
				e = errors.Join(e, release())
			}
			return e
		},
		func() error {
			r, e := PrepareReplacementAtContext(t.Context(), source, root, "denied")
			if r != nil {
				t.Error("denied rooted preparation returned a replacement")
				e = errors.Join(e, r.Close())
			}
			return e
		},
		func() error {
			r, e := PrepareReplacementContext(t.Context(), source, denied)
			if r != nil {
				t.Error("denied preparation returned a replacement")
				e = errors.Join(e, r.Close())
			}
			return e
		},
	} {
		if e := acquire(); !errors.Is(e, os.ErrPermission) {
			t.Fatalf("allocation denial lost its Go error class: %v", e)
		}
	}
	entries, err := os.ReadDir(denied)
	if err != nil || len(entries) != 0 {
		t.Fatalf("denied allocation leaked staging: %v %v", entries, err)
	}
	replacement, err := PrepareReplacementContext(t.Context(), source, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
	named, err := root.OpenFile("replacement", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer named.Close()
	if err = replacementCleanupMetadata(root, source); err == nil {
		t.Fatal("changed private identity accepted")
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err = replacementCleanupMetadata(root, closed); err == nil {
		t.Fatal("closed cleanup capability accepted")
	}
	if _, err = replacementCleanupCapability((*os.File)(nil)); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = replacementHeldIdentity((*os.File)(nil)); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = replacementFinalPath(t.Context(), (*os.File)(nil)); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestReplacementWindowsHeldUnlinkedSource(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		name := filepath.Join(t.TempDir(), "source")
		payload, stream := []byte("held data remains readable after namespace removal"), []byte("held alternate metadata")
		if err := os.WriteFile(name, payload, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name+":metadata", stream, 0600); err != nil {
			t.Fatal(err)
		}
		pointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		source := os.NewFile(uintptr(handle), name)
		defer source.Close()
		if _, err = source.Seek(7, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		// POSIX disposition removes the link when its DELETE handle closes;
		// keep a separate read capability alive to qualify truly nameless input.
		deleteHandle, err := windows.CreateFile(pointer, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS)
		var iosb windows.IO_STATUS_BLOCK
		err = windows.NtSetInformationFile(deleteHandle, &iosb, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileDispositionInformationEx)
		if err = errors.Join(err, windows.CloseHandle(deleteHandle)); err != nil {
			t.Fatalf("required POSIX unlink control: %v", err)
		}
		if _, err = os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source name survived native unlink: %v", err)
		}
		names, err := os.ReadDir(filepath.Dir(name))
		if err != nil || len(names) != 0 {
			t.Fatalf("native unlink directory control: %v %v", names, err)
		}
		got := make([]byte, len(payload))
		if _, err = source.ReadAt(got, 0); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("native held read control: %q %v", got, err)
		}
		var nativeInfo windows.ByHandleFileInformation
		infoErr := windows.GetFileInformationByHandle(handle, &nativeInfo)
		finalName, nameErr := replacementFinalPath(t.Context(), source)
		reopened, reopenErr := reopenReplacementFile(source, windows.GENERIC_READ)
		if reopened != nil {
			backup := &replacementBackup{file: reopened, call: replacementBackupRead}
			_, backupErr := io.Copy(io.Discard, backup)
			backupErr = errors.Join(backupErr, backup.close())
			t.Logf("nameless native reopened BackupRead control: %v", backupErr)
			if !errors.Is(backupErr, windows.ERROR_SHARING_VIOLATION) {
				t.Fatalf("native reopened late acquisition boundary: %v", backupErr)
			}
			reopenErr = errors.Join(reopenErr, reopened.Close())
		}
		t.Logf("nameless native controls: links=%d info_error=%v final_name=%q path_error=%v reopen_error=%v", nativeInfo.NumberOfLinks, infoErr, finalName, nameErr, reopenErr)
		if infoErr != nil || nativeInfo.NumberOfLinks != 0 || nameErr != nil || reopenErr != nil {
			t.Fatalf("native held identity/reopen controls failed: %v %v %v links=%d", infoErr, nameErr, reopenErr, nativeInfo.NumberOfLinks)
		}
		backup := &replacementBackup{file: source, call: replacementBackupRead}
		_, backupErr := io.Copy(io.Discard, backup)
		backupErr = errors.Join(backupErr, backup.close())
		if _, seekErr := source.Seek(7, io.SeekStart); seekErr != nil {
			t.Fatal(seekErr)
		}
		t.Logf("nameless native held BackupRead control: %v", backupErr)
		if !errors.Is(backupErr, windows.ERROR_SHARING_VIOLATION) {
			t.Fatalf("native held late acquisition boundary: %v", backupErr)
		}
		var streamInfo [4096]byte
		streamErr := windows.GetFileInformationByHandleEx(handle, windows.FileStreamInfo, &streamInfo[0], uint32(len(streamInfo)))
		t.Logf("nameless native stream enumeration: error=%v first128=%x", streamErr, streamInfo[:128])
		if streamErr != nil {
			t.Fatal(streamErr)
		}
		streamNameBytes := make([]byte, 0, 30)
		for _, c := range ":metadata:$DATA" {
			streamNameBytes = append(streamNameBytes, byte(c), 0)
		}
		if !bytes.Contains(streamInfo[:], streamNameBytes) {
			t.Fatal("native held stream enumeration lost metadata ADS")
		}
		for _, rootKind := range []string{"original", "reopened"} {
			streamRoot := source
			if rootKind == "reopened" {
				streamRoot, err = reopenReplacementFile(source, windows.GENERIC_READ)
				if err != nil {
					t.Fatal(err)
				}
				defer streamRoot.Close()
			}
			var standard struct {
				AllocationSize, EndOfFile int64
				NumberOfLinks             uint32
				DeletePending, Directory  byte
				_                         [2]byte
			}
			standardErr := windows.GetFileInformationByHandleEx(windows.Handle(streamRoot.Fd()), windows.FileStandardInfo, (*byte)(unsafe.Pointer(&standard)), uint32(unsafe.Sizeof(standard)))
			t.Logf("nameless native %s standard info: %+v error=%v", rootKind, standard, standardErr)
			if standardErr != nil || standard.NumberOfLinks != 0 || standard.DeletePending != 1 {
				t.Fatalf("native delete-pending control: %+v %v", standard, standardErr)
			}
			for _, streamName := range []string{":metadata", ":metadata:$DATA"} {
				unicodeName, unicodeErr := windows.NewNTUnicodeString(streamName)
				if unicodeErr != nil {
					t.Fatal(unicodeErr)
				}
				attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(streamRoot.Fd()), ObjectName: unicodeName}
				var streamHandle windows.Handle
				var streamStatus windows.IO_STATUS_BLOCK
				openErr := windows.NtCreateFile(&streamHandle, windows.GENERIC_READ|windows.SYNCHRONIZE, &attributes, &streamStatus, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
				if openErr == nil {
					_ = windows.CloseHandle(streamHandle)
				}
				t.Logf("nameless native %s relative stream %q: %v", rootKind, streamName, openErr)
				if !errors.Is(openErr, windows.STATUS_DELETE_PENDING) {
					t.Fatalf("native relative ADS acquisition boundary: %v", openErr)
				}

			}
		}
		parent := t.TempDir()
		replacement, err := prepare(source, parent)
		if replacement != nil {
			_ = replacement.Close()
			t.Fatal("late acquisition returned partial replacement")
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Fatalf("late acquisition must preserve native BackupRead denial: %v", err)
		}
		if position, e := source.Seek(0, io.SeekCurrent); e != nil || position != 7 {
			t.Fatalf("caller source position changed: %d %v", position, e)
		}
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed late acquisition leaked stage: %v %v", entries, err)
		}
		if _, err = source.ReadAt(got, 0); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("late acquisition altered held source: %q %v", got, err)
		}
	})
}

func TestReplacementWindowsReparseAndTransferFailures(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err = os.Symlink(source.Name(), link); err != nil {
		t.Fatal(err)
	}
	pointer, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	held := os.NewFile(uintptr(h), link)
	defer held.Close()
	if _, err = prepareReplacementAtContext(t.Context(), held, root, info); !errors.Is(err, ErrUnsupportedReplacement) {
		t.Fatal(err)
	}
	if _, err = prepareReplacementStreamsAtContext(t.Context(), held, root, info); !errors.Is(err, ErrUnsupportedReplacement) {
		t.Fatal(err)
	}
	if err = os.WriteFile(source.Name()+":metadata", []byte("must reach backup writer"), 0600); err != nil {
		t.Fatal(err)
	}
	target, err := os.CreateTemp(t.TempDir(), "closed-target")
	if err != nil {
		t.Fatal(err)
	}
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	if err = copyReplacementStreamsContext(t.Context(), source, target); err == nil {
		t.Fatal("closed native backup destination accepted")
	}
}

func TestReplacementWindowsStreamReadDenial(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	pointer, err := windows.UTF16PtrFromString(source.Name())
	if err != nil {
		t.Fatal(err)
	}
	guard, err := windows.CreateFile(pointer, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	original, err := windows.GetSecurityInfo(guard, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	originalACL, _, err := original.DACL()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := windows.SetSecurityInfo(guard, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, originalACL, nil); e != nil {
			t.Error(e)
		}
		if e := windows.CloseHandle(guard); e != nil {
			t.Error(e)
		}
	}()
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	denied, err := windows.SecurityDescriptorFromString("D:P(D;;0x1;;;WD)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := denied.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetSecurityInfo(guard, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := prepareReplacementStreamsAtContext(t.Context(), source, root, info)
	if file != nil {
		_ = file.Close()
		t.Fatal("failed native transfer returned staging capability")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("source-read ACL control: %v", err)
	}
	// Failed transfer closes its staged data handle; the public owner can discard
	// the private entry immediately without a sharing conflict.
	if err = root.Remove("replacement"); err != nil {
		t.Fatal(err)
	}
}
