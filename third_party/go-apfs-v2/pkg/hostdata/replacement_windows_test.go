package hostdata

import (
	"os"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"golang.org/x/sys/windows"
)

func TestRootReplacementWindowsLargeStream(t *testing.T) {
	source := heldfixture.Source(t, 0600)
	if err := os.WriteFile(source.Name()+":too-large", make([]byte, (8<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	r, err := PrepareReplacementAt(source, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(r.File.Name() + ":too-large")
	if err != nil || len(got) != (8<<20)+1 {
		t.Fatalf("large stream lost: %d %v", len(got), err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cleanup: %v %v", entries, err)
	}
}

func TestRootReplacementWindowsAttributes(t *testing.T) {
	source := heldfixture.Source(t, 0600)
	p, err := windows.UTF16PtrFromString(source.Name())
	if err != nil {
		t.Fatal(err)
	}
	const attributes = windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_READONLY
	if err := windows.SetFileAttributes(p, attributes); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_NORMAL) })
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	r, err := PrepareReplacementAt(source, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.File.WriteAt([]byte("new"), 0); err != nil {
		t.Fatal(err)
	}
	if err := r.RestoreMetadata(); err != nil {
		t.Fatal(err)
	}
	got, err := replacementBasic(r.File)
	want, sourceErr := replacementBasic(source)
	if err != nil || sourceErr != nil || got.Attributes != want.Attributes || got.CreationTime != want.CreationTime {
		t.Fatalf("basic metadata: %#v want %#v: %v, %v", got, want, err, sourceErr)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementWindowsStreamsAndSecurity(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		source := heldfixture.Source(t, 0600)
		if err := os.WriteFile(source.Name()+":test-metadata", []byte("alternate stream"), 0600); err != nil {
			t.Fatal(err)
		}
		// A protected DACL must retain that protection, not inherit new ACEs.
		sd, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		path, err := windows.UTF16PtrFromString(source.Name())
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(path, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
		if err := windows.CloseHandle(handle); err != nil {
			t.Fatal(err)
		}
		r, err := prepare(source, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := r.RestoreMetadata(); err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(r.File.Name() + ":test-metadata"); err != nil || string(got) != "alternate stream" {
			t.Fatalf("stream = %q, %v", got, err)
		}
		flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
		before, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, flags)
		if err != nil {
			t.Fatal(err)
		}
		after, err := windows.GetSecurityInfo(windows.Handle(r.File.Fd()), windows.SE_FILE_OBJECT, flags)
		if err != nil {
			t.Fatal(err)
		}
		if before.String() != after.String() {
			t.Fatalf("security = %s; want %s", after.String(), before.String())
		}

	})
}
