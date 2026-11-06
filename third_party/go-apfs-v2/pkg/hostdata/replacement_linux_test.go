package hostdata

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"golang.org/x/sys/unix"
)

func TestReplacementLinuxACL(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		// Linux POSIX ACL xattr version 2: owner, named user, owning group, mask,
		// other. A named user ensures an extended ACL instead of mode-only data.
		acl := make([]byte, 4+5*8)
		binary.LittleEndian.PutUint32(acl, 2)
		for i, entry := range [][3]uint32{{1, 7, ^uint32(0)}, {2, 4, uint32(os.Getuid() + 1)}, {4, 0, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)}} {
			p := acl[4+i*8:]
			binary.LittleEndian.PutUint16(p, uint16(entry[0]))
			binary.LittleEndian.PutUint16(p[2:], uint16(entry[1]))
			binary.LittleEndian.PutUint32(p[4:], entry[2])
		}
		for _, sourceACL := range []bool{false, true} {
			source := heldfixture.Source(t, 0751)
			if sourceACL {
				if err := unix.Fsetxattr(int(source.Fd()), PosixACLAccessName, acl, 0); err != nil {
					t.Fatal(err)
				}
			}
			parent := t.TempDir()
			if err := unix.Setxattr(parent, "system.posix_acl_default", acl, 0); err != nil {
				t.Fatal(err)
			}
			r, err := prepare(source, parent)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err := r.RestoreMetadata(); err != nil {
				t.Fatal(err)
			}
			value := make([]byte, len(acl)+1)
			n, err := unix.Fgetxattr(int(r.File.Fd()), PosixACLAccessName, value)
			if !sourceACL {
				if err != unix.ENODATA {
					t.Fatalf("unexpected inherited ACL: %v", err)
				}
			} else if err != nil || !bytes.Equal(value[:n], acl) {
				t.Fatalf("ACL changed: %x, %v", value[:n], err)
			}
		}

	})
}
