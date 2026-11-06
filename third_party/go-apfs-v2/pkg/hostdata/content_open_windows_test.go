package hostdata

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestContentOpenWindowsMetadataDenial(t *testing.T) {
	for right, mask := range map[string]uint32{"RC": windows.READ_CONTROL, "REA": windows.FILE_READ_EA, "WD": windows.FILE_WRITE_DATA, "WEA": windows.FILE_WRITE_EA, "WA": windows.FILE_WRITE_ATTRIBUTES} {
		t.Run(right, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file")
			if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			contentOpenWindowsDeny(t, path, mask)
			p, err := windows.UTF16PtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			h, err := windows.CreateFile(p, mask, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
			if err == nil {
				windows.CloseHandle(h)
				t.Fatal("specific denial ineffective", right)
			}
			if !errors.Is(err, os.ErrPermission) {
				t.Fatal(err)
			}
			if right == "RC" || right == "REA" {
				if f, err := os.Open(path); err == nil {
					f.Close()
					t.Fatal("generic-read denial ineffective")
				} else if !errors.Is(err, os.ErrPermission) {
					t.Fatal(err)
				}
			}
			f, err := OpenContentFileRead(root, "file")
			if err != nil {
				t.Fatal("content reader requested unrelated rights", err)
			}
			defer f.Close()
			data, err := io.ReadAll(f)
			if err != nil || string(data) != "unchanged" {
				t.Fatal("content", err, string(data))
			}
		})
	}
}

// Hold the original DACL and a restoration handle before denying access. An
// OWNER RIGHTS ACE makes READ_CONTROL denial effective for the file owner too.
func contentOpenWindowsDeny(t *testing.T, path string, mask uint32) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	saved, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	original, _, err := saved.DACL()
	if err != nil {
		t.Fatal(err)
	}
	principal := "WD"
	if mask == windows.READ_CONTROL {
		principal = "OW"
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(D;;0x%x;;;%s)(A;;FA;;;WD)", mask, principal))
	if err != nil {
		t.Fatal(err)
	}
	denied, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, denied, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, original, nil); err != nil {
			t.Error(err)
		}
	})
}
