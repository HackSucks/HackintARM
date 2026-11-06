package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestReplacementWindowsPreparedUnlinkedSource(t *testing.T) {
	for _, rooted := range []bool{false, true} {
		for _, kind := range []string{"ordinary", "compressed", "sparse", "encrypted", "deny-write", "readonly"} {
			for _, canceled := range []bool{false, true} {
				name := map[bool]string{false: "path", true: "root"}[rooted] + "/" + kind + "/" + map[bool]string{false: "publish", true: "cancel"}[canceled]
				t.Run(name, func(t *testing.T) {
					sourceName := filepath.Join(t.TempDir(), "source")
					payload := []byte("held main data survives namespace unlink")
					stream := bytes.Repeat([]byte("held named metadata"), 4097)
					if err := os.WriteFile(sourceName, payload, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(sourceName+":metadata", stream, 0600); err != nil {
						t.Fatal(err)
					}
					strictWindowsSet(t, sourceName, "replacement.test", []byte("native EA survives unlink"))
					var sparseAllocation int64
					switch kind {
					case "compressed":
						replacementCompress(t, sourceName)
					case "encrypted":
						replacementEncrypt(t, sourceName)
					case "sparse":
						for _, path := range []string{sourceName, sourceName + ":sparse"} {
							file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
							if err != nil {
								t.Fatal(err)
							}
							err = replacementSparse(file)
							if path != sourceName && err == nil {
								_, err = file.WriteAt([]byte("tail"), int64(4<<30)+23)
								if err == nil {
									sparseAllocation = replacementUnlinkedAllocation(t, file)
								}
							}
							if err = errors.Join(err, file.Close()); err != nil {
								t.Fatal(err)
							}
						}
					}
					if kind == "encrypted" {
						probe, e := os.Open(sourceName)
						if e != nil {
							t.Fatal(e)
						}
						value, present, e := ReadXattr(probe, "replacement.test", 128)
						e = errors.Join(e, probe.Close())
						t.Logf("native post-EncryptFile EA: value=%q present=%v error=%v", value, present, e)
						if e != nil {
							t.Fatal(e)
						}
						// Qualify an encrypted file that actually owns the required EA.
						strictWindowsSet(t, sourceName, "replacement.test", []byte("native EA survives unlink"))
						from, e := windows.UTF16PtrFromString(sourceName)
						if e != nil {
							t.Fatal(e)
						}
						reference := filepath.Join(t.TempDir(), "native-copy")
						to, e := windows.UTF16PtrFromString(reference)
						if e != nil {
							t.Fatal(e)
						}
						ok, _, nativeErr := copyFileExW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 0, 0, 0, 0x801)
						if ok == 0 {
							t.Fatal(nativeErr)
						}
						probe, e = os.Open(reference)
						if e != nil {
							t.Fatal(e)
						}
						value, present, e = ReadXattr(probe, "replacement.test", 128)
						e = errors.Join(e, probe.Close())
						t.Logf("native encrypted CopyFileEx EA: value=%q present=%v error=%v", value, present, e)
						if e != nil {
							t.Fatal(e)
						}
					}
					replacementSetCreation(t, sourceName)
					pointer, err := windows.UTF16PtrFromString(sourceName)
					if err != nil {
						t.Fatal(err)
					}
					if kind == "readonly" {
						if err = windows.SetFileAttributes(pointer, windows.FILE_ATTRIBUTE_READONLY); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							if _, e := os.Stat(sourceName); e == nil {
								if e = windows.SetFileAttributes(pointer, windows.FILE_ATTRIBUTE_NORMAL); e != nil {
									t.Error(e)
								}
							}
						})
					}
					if kind == "deny-write" {
						replacementDenyWrites(t, sourceName)
					}
					handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
					if err != nil {
						t.Fatal(err)
					}
					source := os.NewFile(uintptr(handle), sourceName)
					defer source.Close()
					before := replacementNativeSnapshot(t, source)
					value, present, eaErr := ReadXattr(source, "replacement.test", 128)
					if eaErr != nil || !present || string(value) != "native EA survives unlink" {
						t.Fatalf("source preparation EA control: %q %v %v", value, present, eaErr)
					}
					securityFlags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
					security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityFlags)
					if err != nil {
						t.Fatal(err)
					}
					queries := []*windows.LazyProc{replacementQueryUsers, replacementQueryRecovery}
					var keys [2]*replacementEFSList
					if kind == "encrypted" {
						for i, query := range queries {
							keys[i], err = replacementQueryEFS(t.Context(), sourceName, query)
							if err != nil {
								t.Fatal(err)
							}
							if keys[i] != nil {
								defer freeReplacementEFS(keys[i])
							}
						}
					}
					parent := t.TempDir()
					var file *os.File
					var restore func(context.Context) error
					var closeStage func() error
					var publish func() error
					output := filepath.Join(parent, "published")
					if rooted {
						root, e := os.OpenRoot(parent)
						if e != nil {
							t.Fatal(e)
						}
						r, e := PrepareReplacementAtContext(t.Context(), source, root, ".")
						if e != nil {
							_ = root.Close()
							t.Fatal(e)
						}
						file, restore = r.File, r.RestoreMetadataContext
						closeStage = func() error { return errors.Join(r.Close(), root.Close()) }
						publish = func() error { return root.Rename(r.Path, "published") }
					} else {
						r, e := PrepareReplacementContext(t.Context(), source, parent)
						if e != nil {
							t.Fatal(e)
						}
						file, restore, closeStage = r.File, r.RestoreMetadataContext, r.Close
						publish = func() error { return os.Rename(file.Name(), output) }
					}
					defer closeStage()
					deleteHandle, err := windows.CreateFile(pointer, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
					if err != nil {
						t.Fatal(err)
					}
					flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
					var status windows.IO_STATUS_BLOCK
					err = windows.NtSetInformationFile(deleteHandle, &status, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileDispositionInformationEx)
					if err = errors.Join(err, windows.CloseHandle(deleteHandle)); err != nil {
						t.Fatalf("native post-preparation unlink: %v", err)
					}
					if _, err = os.Stat(sourceName); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("source namespace survived unlink: %v", err)
					}
					var nativeInfo windows.ByHandleFileInformation
					if err = windows.GetFileInformationByHandle(handle, &nativeInfo); err != nil || nativeInfo.NumberOfLinks != 0 {
						t.Fatalf("held zero-link control: links=%d %v", nativeInfo.NumberOfLinks, err)
					}
					t.Logf("source after unlink: %#v before=%#v", replacementNativeSnapshot(t, source), before)
					held := make([]byte, len(payload))
					if _, err = source.ReadAt(held, 0); err != nil || !bytes.Equal(held, payload) {
						t.Fatalf("held source changed: %q %v", held, err)
					}
					rewritten := []byte("replacement main bytes")
					if _, err = file.WriteAt(rewritten, 0); err != nil {
						t.Fatal(err)
					}
					if err = file.Truncate(int64(len(rewritten))); err != nil {
						t.Fatal(err)
					}
					if canceled {
						ctx, cancel := context.WithCancel(t.Context())
						cancel()
						if err = restore(ctx); !errors.Is(err, context.Canceled) {
							t.Fatalf("post-unlink cancellation: %v", err)
						}
						if err = closeStage(); err != nil {
							t.Fatal(err)
						}
						entries, e := os.ReadDir(parent)
						if e != nil || len(entries) != 0 {
							t.Fatalf("canceled stage retained: %v %v", entries, e)
						}
						return
					}
					if err = restore(t.Context()); err != nil {
						t.Fatalf("restore from held zero-link source: %v", err)
					}
					restored := replacementNativeSnapshot(t, file)
					t.Logf("target after restore before close: %#v", restored)
					if restored.FileAttributes != before.FileAttributes || restored.CreationTime != before.CreationTime {
						t.Fatalf("restored source metadata: %#v want %#v", restored, before)
					}
					expectedAttributes := replacementUnlinkedRenameControl(t, rooted, kind, before)
					if err = file.Close(); err != nil {
						t.Fatal(err)
					}
					closed := replacementUnlinkedPathSnapshot(t, file.Name())
					t.Logf("target after close before rename: %#v", closed)
					if closed.FileAttributes != before.FileAttributes || closed.CreationTime != before.CreationTime {
						t.Fatalf("closed source metadata: %#v want %#v", closed, before)
					}
					if err = publish(); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { replacementResetTestFile(t, output) })
					published := replacementUnlinkedPathSnapshot(t, output)
					t.Logf("target after rename before cleanup: %#v", published)
					if published.FileAttributes != expectedAttributes || published.CreationTime != before.CreationTime {
						t.Fatalf("native publication transition: %#v want attributes=%#x creation=%#v", published, expectedAttributes, before.CreationTime)
					}
					if err = closeStage(); err != nil {
						t.Fatal(err)
					}
					result, err := os.Open(output)
					if err != nil {
						t.Fatal(err)
					}
					defer result.Close()
					actual := replacementNativeSnapshot(t, result)
					if actual.FileAttributes != published.FileAttributes || actual.CreationTime != published.CreationTime {
						t.Fatalf("publication cleanup changed metadata: %#v want %#v", actual, published)
					}
					copiedSecurity, err := windows.GetSecurityInfo(windows.Handle(result.Fd()), windows.SE_FILE_OBJECT, securityFlags)
					if err != nil {
						t.Fatal(err)
					}
					if copiedSecurity.String() != security.String() {
						t.Fatalf("published security: %s want %s", copiedSecurity.String(), security.String())
					}
					got, err := io.ReadAll(result)
					if err != nil || !bytes.Equal(got, rewritten) {
						t.Fatalf("published data: %q %v", got, err)
					}
					got, err = os.ReadFile(output + ":metadata")
					if err != nil || !bytes.Equal(got, stream) {
						t.Fatalf("published named metadata: %d %v", len(got), err)
					}
					ea, present, err := ReadXattr(result, "replacement.test", 128)
					if err != nil || !present || string(ea) != "native EA survives unlink" {
						t.Fatalf("published EA: %q %v %v", ea, present, err)
					}
					if kind == "sparse" {
						named, e := os.Open(output + ":sparse")
						if e != nil {
							t.Fatal(e)
						}
						defer named.Close()
						if allocation := replacementUnlinkedAllocation(t, named); allocation != sparseAllocation {
							t.Fatalf("sparse ADS allocation changed: %d want %d", allocation, sparseAllocation)
						}
						var tail [4]byte
						_, e = named.ReadAt(tail[:], int64(4<<30)+23)
						if e = errors.Join(e, named.Close()); e != nil || string(tail[:]) != "tail" {
							t.Fatalf("published sparse stream: %q %v", tail, e)
						}
					}
					if kind == "encrypted" {
						for i, query := range queries {
							copied, e := replacementQueryEFS(t.Context(), output, query)
							if e != nil {
								t.Fatal(e)
							}
							equal := replacementEFSKeysEqual(keys[i], copied)
							if copied != nil {
								freeReplacementEFS(copied)
							}
							if !equal {
								t.Fatal("post-unlink EFS recipient/recovery keys changed")
							}
						}
					}
					// Cleanup of a committed stage must leave the published metadata untouched.
					if err = closeStage(); err != nil {
						t.Fatal(err)
					}
					final := replacementNativeSnapshot(t, result)
					if final.FileAttributes != actual.FileAttributes || final.CreationTime != actual.CreationTime {
						t.Fatalf("committed cleanup changed metadata: %#v %#v", final, actual)
					}
					entries, err := os.ReadDir(parent)
					if err != nil || len(entries) != 1 || entries[0].Name() != "published" {
						t.Fatalf("private stage survived publication: %v %v", entries, err)
					}
				})
			}
		}
	}
}

func replacementUnlinkedAllocation(t *testing.T, file *os.File) int64 {
	t.Helper()
	var info struct {
		AllocationSize, EndOfFile int64
		NumberOfLinks             uint32
		DeletePending, Directory  byte
		_                         [2]byte
	}
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileStandardInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		t.Fatal(err)
	}
	return info.AllocationSize
}

func replacementUnlinkedPathSnapshot(t *testing.T, name string) windows.ByHandleFileInformation {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), name)
	defer file.Close()
	return replacementNativeSnapshot(t, file)
}

// This independent control uses only native file setup and the caller's actual
// publication operation. Windows may change ARCHIVE during rename; compare the
// complete resulting attributes, never a masked subset of the original flags.
func replacementUnlinkedRenameControl(t *testing.T, rooted bool, kind string, source windows.ByHandleFileInformation) uint32 {
	t.Helper()
	parent := t.TempDir()
	stage := filepath.Join(parent, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(stage, "data")
	output := filepath.Join(parent, "published")
	if err := os.WriteFile(name, []byte("replacement main bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	switch kind {
	case "encrypted":
		replacementEncrypt(t, name)
	case "compressed":
		replacementCompress(t, name)
	case "sparse":
		f, err := os.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = errors.Join(replacementSparse(f), f.Close()); err != nil {
			t.Fatal(err)
		}
	}
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(pointer, windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = errors.Join(windows.SetFileTime(h, &source.CreationTime, nil, nil), windows.CloseHandle(h)); err != nil {
		t.Fatal(err)
	}
	if err = windows.SetFileAttributes(pointer, source.FileAttributes); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, path := range []string{name, output} {
			if _, e := os.Stat(path); e == nil {
				replacementResetTestFile(t, path)
			}
		}
	})
	if kind == "deny-write" {
		replacementDenyWrites(t, name)
	}
	before := replacementUnlinkedPathSnapshot(t, name)
	if before.FileAttributes != source.FileAttributes || before.CreationTime != source.CreationTime {
		t.Fatalf("native rename setup differs: %#v want %#v", before, source)
	}
	if rooted {
		root, e := os.OpenRoot(parent)
		if e != nil {
			t.Fatal(e)
		}
		err = errors.Join(root.Rename(filepath.Join("stage", "data"), "published"), root.Close())
	} else {
		err = os.Rename(name, output)
	}
	if err != nil {
		t.Fatalf("independent native rename: %v", err)
	}
	after := replacementUnlinkedPathSnapshot(t, output)
	t.Logf("independent native rename rooted=%v kind=%s before=%#v after=%#v", rooted, kind, before, after)
	if after.CreationTime != before.CreationTime {
		t.Fatalf("native rename changed creation time: %#v %#v", before, after)
	}
	return after.FileAttributes
}

func TestReplacementWindowsEncryptedLateUnlink(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		name := filepath.Join(t.TempDir(), "encrypted")
		payload := []byte("held encrypted data")
		if err := os.WriteFile(name, payload, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name+":metadata", []byte("encrypted ADS"), 0600); err != nil {
			t.Fatal(err)
		}
		replacementEncrypt(t, name)
		pointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			t.Fatal(err)
		}
		readHandle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		source := os.NewFile(uintptr(readHandle), name)
		defer source.Close()
		h, err := windows.CreateFile(pointer, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS)
		err = windows.NtSetInformationFile(h, &windows.IO_STATUS_BLOCK{}, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileDispositionInformationEx)
		if err = errors.Join(err, windows.CloseHandle(h)); err != nil {
			t.Fatal(err)
		}
		if _, err = os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("native encrypted unlink: %v", err)
		}
		held := replacementNativeSnapshot(t, source)
		if held.NumberOfLinks != 0 || held.FileAttributes&windows.FILE_ATTRIBUTE_ENCRYPTED == 0 {
			t.Fatalf("held encrypted zero-link control: %#v", held)
		}
		got := make([]byte, len(payload))
		if _, err = source.ReadAt(got, 0); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("native encrypted held read: %q %v", got, err)
		}
		finalName, err := replacementFinalPath(t.Context(), source)
		if err != nil {
			t.Fatal(err)
		}
		from, err := windows.UTF16PtrFromString(finalName)
		if err != nil {
			t.Fatal(err)
		}
		nativeOutput := filepath.Join(t.TempDir(), "native-copy")
		to, err := windows.UTF16PtrFromString(nativeOutput)
		if err != nil {
			t.Fatal(err)
		}
		ok, _, nativeErr := copyFileExW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 0, 0, 0, 0x801)
		t.Logf("native encrypted zero-link CopyFileEx: name=%q result=%d error=%v", finalName, ok, nativeErr)
		if ok != 0 || !errors.Is(nativeErr, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("native encrypted late acquisition boundary: result=%d error=%v", ok, nativeErr)
		}
		if _, err = os.Stat(nativeOutput); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("native denied copy created output: %v", err)
		}
		parent := t.TempDir()
		replacement, err := prepare(source, parent)
		if replacement != nil {
			_ = replacement.Close()
			t.Fatal("late encrypted acquisition returned partial replacement")
		}
		if !errors.Is(err, errReplacementSourcePathMissing) {
			t.Fatalf("encrypted zero-link rejection: %v", err)
		}
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Fatalf("encrypted late acquisition leaked stage: %v %v", entries, err)
		}
		if _, err = source.ReadAt(got, 0); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("late encrypted acquisition altered source: %q %v", got, err)
		}
	})
}
