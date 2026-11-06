package decmpfs

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestNativeLZ4Storage(t *testing.T) {
	f, e := os.Open("../../testdata/appledouble/native/compression-lz4.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var c struct {
		Kernel []struct {
			Name, Filesystem       string
			Type                   uint32
			Plain, Attribute, Fork []byte
			Exit                   int
		}
	}
	if e = json.NewDecoder(z).Decode(&c); e != nil {
		t.Fatal(e)
	}
	if len(c.Kernel) != 1172 {
		t.Fatal("incomplete native storage corpus")
	}
	for _, s := range c.Kernel {
		t.Run(s.Filesystem+"/"+s.Name, func(t *testing.T) {
			data := s.Attribute
			if s.Type == 16 {
				data = s.Fork
			}
			method, e := MethodFor(s.Type)
			if e != nil {
				t.Fatal(e)
			}
			h, e := NewHandle(&memSource{data: data}, uint64(len(s.Plain)), method)
			if e != nil {
				t.Fatal(e)
			}
			defer h.Close()
			got := make([]byte, len(s.Plain))
			at := 0
			for at < len(got) {
				p := got[at:min(at+4331, len(got))]
				var n int
				n, e = h.ReadSegmentData(0, p)
				at += n
				if e != nil {
					break
				}
				if n != len(p) {
					t.Fatal("unexpected short decode")
				}
			}
			if (e == nil) != (s.Exit == 0) {
				t.Fatalf("native exit %d Go error %v", s.Exit, e)
			}
			if e == nil && !bytes.Equal(got, s.Plain) {
				t.Fatal("kernel readback differs")
			}
		})
	}
}
func TestLZ4MethodAndStorage(t *testing.T) {
	for _, kind := range []uint32{15, 16} {
		m, e := MethodFor(kind)
		if e != nil || m != MethodLZ4 {
			t.Fatal(m, e)
		}
		if StoresDataInResourceFork(kind) != (kind == 16) {
			t.Fatal("storage classification")
		}
	}
	for _, n := range []int{-1, 2} {
		size := n
		if e := Decompress([]byte{0xff, 'a'}, MethodLZ4, make([]byte, 1), &size); e == nil {
			t.Fatal("invalid capacity accepted")
		}
	}
	size := 1
	out := make([]byte, 1)
	if e := Decompress([]byte{0xff, 'a'}, MethodLZ4, out, &size); e != nil || size != 1 || string(out) != "a" {
		t.Fatal(fmt.Sprint(size, out, e))
	}
}
