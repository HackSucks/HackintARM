package hfsplus

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Replay independently captured native setter/getter observations on every OS.
func TestImageFinderInfoNativeCapture(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/hfs-finderinfo.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var fixture struct {
		Host, Compiler, SDK, Revision string
		Cases                         []struct {
			Kind, Form, Input, FinalFlags string
			Native                        struct {
				Code, Errno, Length, GetErrno int
				Flags                         uint32
				Value                         string
			}
		}
	}
	if err = json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 80 || fixture.Host == "" || fixture.Compiler == "" || fixture.SDK == "" || len(fixture.Revision) != 40 {
		t.Fatal("incomplete native evidence")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Kind+"/"+c.Form, func(t *testing.T) {
			parts := strings.Split(c.Kind, "/")
			kind := parts[1]
			raw, err := hex.DecodeString(c.Input)
			if err != nil {
				t.Fatal(err)
			}
			e := &Entry{Name: "item", Mode: 0644, Data: []byte("data"), Xattrs: map[string][]byte{finderInfoName: raw}}
			switch kind {
			case "root", "directory":
				e.Mode = os.ModeDir | 0755
				e.Data = nil
			case "symlink":
				e.Mode = os.ModeSymlink | 0755
				e.Data = []byte("target")
			}
			if c.FinalFlags != "-" {
				flags, err := strconv.ParseUint(c.FinalFlags, 10, 32)
				if err != nil {
					t.Fatal(err)
				}
				n := uint32(flags)
				e.BSDFlags = &n
			}
			root := &Entry{Mode: os.ModeDir | 0755, Children: []*Entry{e}}
			name := "item"
			if kind == "root" {
				root = e
				name = "."
			}
			if kind == "hardlink" {
				e.LinkGroup = 1
				alias := *e
				alias.Name = "alias"
				root.Children = append(root.Children, &alias)
			}
			w := &memWriterAt{}
			err = CreateImage(w, 0, "FINDER", root, &CreateOptions{CaseInsensitive: parts[0] == "hfsplus"})
			if c.Native.Code != 0 {
				if err == nil {
					t.Fatal("native rejected value accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			v, err := New(bytes.NewReader(w.b))
			if err != nil {
				t.Fatal(err)
			}
			attrs, err := v.Xattrs(name)
			if err != nil {
				t.Fatal(err)
			}
			value, exists := attrs[finderInfoName]
			if exists != (c.Native.Length >= 0) || hex.EncodeToString(value) != c.Native.Value {
				t.Fatalf("FinderInfo differs from native: %x", value)
			}
			m, err := v.Metadata(name)
			if err != nil {
				t.Fatal(err)
			}
			if m.BSDFlags != c.Native.Flags {
				t.Fatalf("flags %x != %x", m.BSDFlags, c.Native.Flags)
			}
		})
	}
}
