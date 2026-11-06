package hostdata

import (
	"bytes"
	"golang.org/x/sys/unix"
	"os"

	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestReplacementDarwinDeniesWriteAfterRestore(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		source := heldfixture.Source(t, 0751)
		if out, err := cirunner.Command("/bin/chmod", "+a", "everyone deny write", source.Name()).CombinedOutput(); err != nil {
			t.Fatalf("set ACL: %v %s", err, out)
		}
		from, err := NewHeldMetadata(source)
		if err != nil {
			t.Fatal(err)
		}
		original, err := from.CaptureACL()
		if err != nil {
			t.Fatal(err)
		}
		if f, err := os.OpenFile(source.Name(), os.O_WRONLY, 0); err == nil {
			f.Close()
			t.Fatal("source write denial ineffective")
		}
		r, err := prepare(source, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := r.File.WriteAt([]byte("changed"), 0); err != nil {
			t.Fatal(err)
		}
		if err := r.File.Truncate(7); err != nil {
			t.Fatal(err)
		}
		to, err := NewHeldMetadata(r.File)
		if err != nil {
			t.Fatal(err)
		}
		temporary, err := to.CaptureACL()
		if err != nil {
			t.Fatal(err)
		}
		if temporary.Security.ACL != nil {
			t.Fatal("source ACL installed before writes completed")
		}
		if err := r.RestoreMetadata(); err != nil {
			t.Fatal(err)
		}
		restored, err := to.CaptureACL()
		if err != nil {
			t.Fatal(err)
		}
		a, err := original.MarshalDarwinACLAttributes()
		if err != nil {
			t.Fatal(err)
		}
		b, err := restored.MarshalDarwinACLAttributes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("security changed: %x -> %x", a, b)
		}
		if f, err := os.OpenFile(r.File.Name(), os.O_WRONLY, 0); err == nil {
			f.Close()
			t.Fatal("replacement write denial not restored")
		}
		got, err := os.ReadFile(r.File.Name())
		if err != nil || string(got) != "changed" {
			t.Fatal(string(got), err)
		}
		got, err = os.ReadFile(source.Name())
		if err != nil || string(got) == "changed" {
			t.Fatal("source changed", err)
		}
	})
}

func TestReplacementDarwinACLRestoreFailures(t *testing.T) {
	for _, kind := range []string{"source-closed", "target-closed", "source-read-security", "target-protected"} {
		t.Run(kind, func(t *testing.T) {
			source, target := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
			switch kind {
			case "source-closed":
				source.Close()
			case "target-closed":
				target.Close()
			case "target-protected":
				if err := unix.Fchflags(int(target.Fd()), unix.UF_IMMUTABLE); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := unix.Chflags(target.Name(), 0); err != nil {
						t.Error(err)
					}
				})
			case "source-read-security":
				file, right := source, "readsecurity"
				if out, err := cirunner.Command("/bin/chmod", "+a", "everyone deny "+right, file.Name()).CombinedOutput(); err != nil {
					t.Fatalf("deny security: %v %s", err, out)
				}
				t.Cleanup(func() {
					if out, err := cirunner.Command("/bin/chmod", "-N", file.Name()).CombinedOutput(); err != nil {
						t.Errorf("reset security: %v %s", err, out)
					}
				})
			}
			err := restoreReplacementACL(source, target)
			// Removing an already absent ACL is authorized even on an immutable
			// file owned by this process. Do not invent a permission failure.
			if (err == nil) != (kind == "target-protected") {
				t.Fatalf("unexpected ACL restoration result: %v", err)
			}
			before, err := os.ReadFile(source.Name())
			if err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(target.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("ACL failure changed data")
			}
		})
	}
}
