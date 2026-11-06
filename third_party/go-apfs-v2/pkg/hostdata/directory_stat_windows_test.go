package hostdata

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestCopyDirectoryStatWindows(t *testing.T) {
	source, target := directoryStatFixture(t), directoryStatFixture(t)
	const attrs = windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | windows.FILE_ATTRIBUTE_READONLY
	for i, f := range []*os.File{source, target} {
		stream, err := windows.UTF16PtrFromString(f.Name() + ":directory-stat")
		if err != nil {
			t.Fatal(err)
		}
		streamHandle, err := windows.CreateFile(stream, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.CREATE_ALWAYS, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			t.Fatal(err)
		}
		streamFile := os.NewFile(uintptr(streamHandle), f.Name()+":directory-stat")
		_, err = streamFile.WriteString(f.Name())
		_ = streamFile.Close()
		if err != nil {
			t.Fatal(err)
		}
		p, err := windows.UTF16PtrFromString(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		h, err := windows.CreateFile(p, windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			t.Fatal(err)
		}
		created := windows.NsecToFiletime(time.Unix(1600000000+int64(i)*100, 123456700).UnixNano())
		access := windows.NsecToFiletime(time.Unix(1650000000+int64(i)*100, 123456700).UnixNano())
		modified := windows.NsecToFiletime(time.Unix(1660000000+int64(i)*100, 987654300).UnixNano())
		err = windows.SetFileTime(h, &created, &access, &modified)
		_ = windows.CloseHandle(h)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := windows.SetFileAttributes(p, attrs); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { _ = windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_NORMAL) })
	}
	// Protect the target's DACL so an accidental security copy is observable.
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	security, err := windows.GetSecurityInfo(windows.Handle(target.Fd()), windows.SE_FILE_OBJECT, flags)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := security.DACL()
	if err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(target.Name())
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	_ = windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	security, err = windows.GetSecurityInfo(windows.Handle(target.Fd()), windows.SE_FILE_OBJECT, flags)
	if err != nil {
		t.Fatal(err)
	}
	before, err := replacementBasic(target)
	if err != nil {
		t.Fatal(err)
	}
	want, err := replacementBasic(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := CopyDirectoryStat(source, target); err != nil {
		t.Fatal(err)
	}
	got, err := replacementBasic(target)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastAccessTime != want.LastAccessTime || got.LastWriteTime != want.LastWriteTime || got.Attributes != attrs|windows.FILE_ATTRIBUTE_DIRECTORY || got.CreationTime != before.CreationTime {
		t.Fatalf("metadata: %#v; source %#v; target before %#v", got, want, before)
	}
	after, err := windows.GetSecurityInfo(windows.Handle(target.Fd()), windows.SE_FILE_OBJECT, flags)
	if err != nil || after.String() != security.String() {
		t.Fatalf("security changed: %v %v", after, err)
	}
	if data, err := os.ReadFile(target.Name() + ":directory-stat"); err != nil || string(data) != target.Name() {
		t.Fatalf("stream changed: %q %v", data, err)
	}
}
