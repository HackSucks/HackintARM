// Package entrytype constructs disposable native authorization fixtures.
package entrytype

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"

	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

var Cases = []string{"ordinary", "read", "readattr", "readsecurity", "readextattr", "write", "writeattr", "writesecurity", "writeextattr", "readattr+readsecurity", "read+readsecurity+readextattr", "directory", "symlink", "dangling", "fifo", "socket", "missing"}

// Make creates file within an existing directory. Cleanup must run even when an
// observation fails; it removes fixture ACLs before the caller removes the tree.
func Make(parent, name string) (func() error, error) {
	path := filepath.Join(parent, "file")
	hasACL := false
	cleanup := func() error {
		if !hasACL {
			return nil
		}
		b, err := cirunner.Command("/bin/chmod", "-N", path).CombinedOutput()
		if err != nil {
			return fmt.Errorf("restore fixture ACL: %w: %s", err, b)
		}
		return nil
	}
	var err error
	switch name {
	case "directory":
		err = os.Mkdir(path, 0700)
	case "symlink", "dangling":
		if name == "symlink" {
			err = os.WriteFile(filepath.Join(parent, "target"), []byte("unchanged"), 0600)
		}
		if err == nil {
			err = os.Symlink("target", path)
		}
	case "fifo":
		err = unix.Mkfifo(path, 0600)
	case "socket":
		var fd int
		fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err == nil {
			err = unix.Bind(fd, &unix.SockaddrUnix{Name: path})
			_ = unix.Close(fd)
		}
	case "missing":
	default:
		err = os.WriteFile(path, []byte("unchanged"), 0600)
		if err == nil && name != "ordinary" {
			hasACL = true
			b, e := cirunner.Command("/bin/chmod", "+a", "everyone deny "+strings.ReplaceAll(name, "+", ","), path).CombinedOutput()
			if e != nil {
				err = fmt.Errorf("fixture ACL: %w: %s", e, b)
			}
		}
	}
	return cleanup, err
}
