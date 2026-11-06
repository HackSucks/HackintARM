package hfsplus

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"
)

func TestLookupNameValidation(t *testing.T) {
	for _, c := range []struct {
		name string
		want error
	}{{"", syscall.ENOENT}, {"a/b", syscall.EINVAL}, {"a\x00b", syscall.EINVAL}, {"x\x80y", nil}, {strings.Repeat("a", 254) + "\x80", syscall.ENAMETOOLONG}, {strings.Repeat("a", 255), nil}, {strings.Repeat("a", 256), syscall.ENAMETOOLONG}, {strings.Repeat("é", 127), nil}, {strings.Repeat("é", 128), syscall.ENAMETOOLONG}, {strings.Repeat("😀", 127), nil}, {strings.Repeat("😀", 128), syscall.ENAMETOOLONG}, {"x\u0378y", nil}} {
		if e := ValidateLookupName(c.name); !errors.Is(e, c.want) {
			t.Fatalf("%q got%v want%v", c.name, e, c.want)
		}
	}
}
func TestIllegalUTF8CatalogAliases(t *testing.T) {
	for _, c := range [][2]string{{"x\x80y", "x%80y"}, {"x\xc0\xafy", "x%C0%AFy"}, {"x\xe0\x80\xafy", "x%E0%80%AFy"}, {"x\xed\xa0\x80y", "x%ED%A0%80y"}, {"x\xf4\x90\x80\x80y", "x%F4%90%80%80y"}, {"x\xc3", "x%C3"}, {"x\ufffey", "x%EF%BF%BEy"}, {"x\uffffy", "x%EF%BF%BFy"}} {
		for _, sensitive := range []bool{false, true} {
			if CompareNames(c[0], c[1], sensitive) != 0 {
				t.Fatalf("native percent alias %x", c[0])
			}
			if CompareNames(c[0], "x�y", sensitive) == 0 {
				t.Fatal("invalidbytes aliased replacementscalar")
			}
		}
	}
}

func TestNativeNormalizedComponentReader(t *testing.T) {
	image := &memWriterAt{}
	root := &Entry{Children: []*Entry{{Name: "x%80y", Data: []byte("native percent alias")}}}
	if err := CreateImage(image, 0, "Names", root, nil); err != nil {
		t.Fatal(err)
	}
	volume, err := New(bytes.NewReader(image.b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = volume.lookup("x\x80y"); err != nil {
		t.Fatal("low-level native percent alias", err)
	}
	if _, err = volume.ReadFile("x\x80y"); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal("io/fs raw invalidUTF8 contract", err)
	}
	name, err := NormalizeLookupName("x\x80y")
	if err != nil || name != "x%80y" {
		t.Fatal(name, err)
	}
	data, err := volume.ReadFile(name)
	if err != nil || string(data) != "native percent alias" {
		t.Fatal(string(data), err)
	}
	if _, err = volume.lookup(strings.Repeat("a", 256)); !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Fatal("low-level component length", err)
	}
}
