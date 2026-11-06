package hostdata

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func strictListRangeError() error { return windows.STATUS_BUFFER_TOO_SMALL }

// One independent multi-entry NT query; the implementation uses single-entry
// cursor queries. Decode the native offset chain without production helpers.
func strictListWindowsOracle(t *testing.T, path string) []string {
	t.Helper()
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		t.Fatal(e)
	}
	h, e := windows.CreateFile(p, windows.FILE_READ_EA|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	b := make([]byte, 128<<10)
	var status windows.IO_STATUS_BLOCK
	e = windows.NtQueryEaFile(h, &status, &b[0], uint32(len(b)), false, nil, 0, nil, true)
	if errors.Is(e, windows.STATUS_NO_EAS_ON_FILE) || errors.Is(e, windows.STATUS_NO_MORE_EAS) {
		return []string{}
	}
	if e != nil {
		t.Fatal(e)
	}
	if status.Information > uintptr(len(b)) {
		t.Fatal("native length", status.Information)
	}
	b = b[:status.Information]
	names := []string{}
	for {
		if len(b) < 9 {
			t.Fatal("native record too short")
		}
		n := int(b[5])
		end := 9 + n + int(binary.LittleEndian.Uint16(b[6:]))
		if n == 0 || end > len(b) || b[8+n] != 0 {
			t.Fatal("native record framing")
		}
		names = append(names, string(b[8:8+n]))
		next := int(binary.LittleEndian.Uint32(b))
		if next == 0 {
			break
		}
		if next < end || next%4 != 0 || next >= len(b) {
			t.Fatal("native offset", next, end, len(b))
		}
		b = b[next:]
	}
	return names
}
func TestStrictXattrListWindowsNative(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			var f *os.File
			if kind == "file" {
				f = strictWindowsFile(t, path)
			} else {
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
				h, e := openXattrPath(path, windows.FILE_READ_EA)
				if e != nil {
					t.Fatal(e)
				}
				f = os.NewFile(uintptr(h), path)
				defer f.Close()
			}
			if names, e := ListXattrNames(f, 0); e != nil || names == nil || len(names) != 0 {
				t.Fatal(names, e)
			}
			fixtures := []string{"user.z", "user.Alpha", "USER.NUMBER_1", "user.empty", strings.Repeat("n", 254)}
			for _, n := range fixtures {
				strictWindowsSet(t, path, n, []byte{1})
			}
			strictWindowsSet(t, path, "user.empty", nil)
			// A large value must not consume the names budget or require a second record.
			strictWindowsSet(t, path, "user.large", make([]byte, 60000))
			want := strictListWindowsOracle(t, path)
			budget := 0
			for _, n := range want {
				budget += len(n) + 1
			}
			got, e := ListXattrNames(f, budget)
			if e != nil || !reflect.DeepEqual(got, want) || len(got) != 5 {
				t.Fatal(got, want, e)
			}
			if n, e := ListXattrNames(f, budget-1); n != nil || !errors.Is(e, ErrXattrTooLarge) {
				t.Fatal(n, e)
			}
			if n, e := ListXattrNames(f, 0); n != nil || !errors.Is(e, ErrXattrTooLarge) {
				t.Fatal(n, e)
			}
			moved := path + "-moved"
			if e := os.Rename(path, moved); e != nil {
				t.Fatal(e)
			}
			strictWindowsFile(t, path)
			strictWindowsSet(t, path, "user.decoy", []byte{1})
			if n, e := ListXattrNames(f, budget); e != nil || !reflect.DeepEqual(n, want) {
				t.Fatal("reopened pathname", n, e)
			}
			if kind == "file" {
				alias := path + "-alias"
				if e := os.Link(moved, alias); e != nil {
					t.Fatal(e)
				}
				strictWindowsSet(t, alias, "user.alias", []byte{1})
				if n, e := ListXattrNames(f, MaxXattrListSize); e != nil || !slices.ContainsFunc(n, func(name string) bool { return strings.EqualFold(name, "user.alias") }) {
					t.Fatal(n, e)
				}
				if b, e := io.ReadAll(f); e != nil || string(b) != "contents" {
					t.Fatal("data/offset changed", string(b), e)
				}
			}
			t.Logf("%s native names=%q budget=%d; cursor/batch and held identity agree", kind, want, budget)
		})
	}
	if n, e := listVisibleXattrFD(-1, 100); n != nil || e == nil {
		t.Fatal(n, e)
	}
}
func TestStrictXattrListWindowsLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	strictWindowsFile(t, target)
	strictWindowsSet(t, target, "user.target", []byte{1})
	if e := os.Symlink(target, link); e != nil {
		t.Fatal("required symlink fixture", e)
	}
	strictWindowsSet(t, link, "user.link", []byte{2})
	h, e := openXattrPath(link, windows.FILE_READ_EA)
	if e != nil {
		t.Fatal(e)
	}
	held := os.NewFile(uintptr(h), link)
	defer held.Close()
	want := strictListWindowsOracle(t, link)
	if n, e := ListXattrNames(held, MaxXattrListSize); e != nil || !reflect.DeepEqual(n, want) {
		t.Fatal(n, want, e)
	}
	if e := os.Rename(link, link+"-moved"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	strictWindowsSet(t, link, "user.decoy", []byte{3})
	if n, e := ListXattrNames(held, MaxXattrListSize); e != nil || !reflect.DeepEqual(n, want) {
		t.Fatal("link identity", n, e)
	}
	followed, e := os.Open(link)
	if e != nil {
		t.Fatal(e)
	}
	defer followed.Close()
	if n, e := ListXattrNames(followed, MaxXattrListSize); e != nil || !reflect.DeepEqual(n, strictListWindowsOracle(t, target)) {
		t.Fatal(n, e)
	}
}
func TestStrictXattrListWindowsStatuses(t *testing.T) {
	for _, c := range []struct {
		err     error
		restart bool
		want    error
	}{
		{nil, true, nil}, {windows.STATUS_NO_MORE_EAS, false, io.EOF}, {windows.STATUS_NO_EAS_ON_FILE, true, io.EOF},
		{windows.STATUS_NO_EAS_ON_FILE, false, ErrXattrChanged}, {windows.STATUS_EA_LIST_INCONSISTENT, false, windows.STATUS_EA_LIST_INCONSISTENT},
		{windows.STATUS_ACCESS_DENIED, false, windows.STATUS_ACCESS_DENIED},
	} {
		e := listWindowsEAError(c.err, c.restart)
		if !errors.Is(e, c.want) {
			t.Fatal(c, e)
		}
		if c.want == ErrXattrChanged && !errors.Is(e, c.err) {
			t.Fatal("lost status", e)
		}
	}
}

func TestStrictXattrListWindowsNameBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary")
	file := strictWindowsFile(t, path)
	accepted, refused := strings.Repeat("a", 254), strings.Repeat("b", 255)
	strictWindowsSet(t, path, accepted, []byte("keep"))
	before := strictListWindowsOracle(t, path)
	if err := strictWindowsSetResult(t, path, refused, []byte("reject")); !errors.Is(err, windows.STATUS_INVALID_EA_NAME) {
		t.Fatalf("255-byte native name: %T %v", err, err)
	}
	if _, _, err := XattrSize(file, refused); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("255-byte named query", err)
	}
	after, err := ListXattrNames(file, MaxXattrListSize)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed set changed namespace", before, after, err)
	}
	value, present, err := ReadXattr(file, accepted, 4)
	if err != nil || !present || string(value) != "keep" {
		t.Fatal(value, present, err)
	}
	t.Log("254-byte native name accepted and readable; 255-byte native name refused without changing metadata")
}
