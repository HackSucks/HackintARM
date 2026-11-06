package apfs

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestLookupNameValidation(t *testing.T) {
	for _, c := range []struct {
		name string
		want error
	}{{"", syscall.ENOENT}, {"a/b", syscall.EINVAL}, {"a\x00b", syscall.EINVAL}, {"x\x80y", syscall.ENOENT}, {strings.Repeat("a", 256) + "\x80", syscall.ENOENT}, {strings.Repeat("a", 255), nil}, {strings.Repeat("a", 256), syscall.ENAMETOOLONG}, {strings.Repeat("é", 255), nil}, {strings.Repeat("e\u0301", 128), syscall.ENAMETOOLONG}, {strings.Repeat("😀", 127), nil}, {strings.Repeat("😀", 128), syscall.ENAMETOOLONG}, {"x\u0378y", nil}} {
		if e := ValidateLookupName(c.name); !errors.Is(e, c.want) {
			t.Fatalf("%q got%v want%v", c.name, e, c.want)
		}
	}
}

type unexpectedNameRead struct{}

func (unexpectedNameRead) ReadAt([]byte, int64) (int, error) {
	panic("invalid component reached image reader")
}
func TestDirectoryLookupValidatesBeforeReading(t *testing.T) {
	tree := &FileSystemBTree{}
	for _, c := range []struct {
		name string
		want error
	}{{"x\x80y", syscall.ENOENT}, {strings.Repeat("a", 256), syscall.ENAMETOOLONG}, {"a\x00b", syscall.EINVAL}, {"a/b", syscall.EINVAL}} {
		if _, err := tree.DirectoryEntryRecordByUTF8Name(unexpectedNameRead{}, 2, c.name, 0); !errors.Is(err, c.want) {
			t.Fatal(c.name, err, c.want)
		}
	}
}
