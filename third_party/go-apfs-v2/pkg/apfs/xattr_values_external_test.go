package apfs_test

import (
	"bytes"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func TestVolumeXattrValues(t *testing.T) {
	image, _ := seedImage(t)
	container, e := apfs.Open(bytes.NewReader(image), &apfs.OpenOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer container.Close()
	volumes, e := container.Volumes()
	if e != nil {
		t.Fatal(e)
	}
	v := volumes[0]
	attrs, e := v.XattrValues("tagged")
	if e != nil {
		t.Fatal(e)
	}
	value := attrs["com.example.tag"]
	if value == nil || value.Size() != 5 {
		t.Fatal(attrs)
	}
	b := make([]byte, 5)
	if n, e := value.ReadAt(b, 0); e != nil || n != 5 || string(b) != "value" {
		t.Fatal(n, e)
	}
	if _, e = v.XattrValues("missing"); e == nil {
		t.Fatal("missing path")
	}
	if _, e = v.XattrValues("../bad"); e == nil {
		t.Fatal("unsafe path")
	}
}
