package appledouble

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The probe records every sidecar pkgbuild wrote for the links fixture.
type probe struct {
	Payload []struct {
		Name        string `json:"name"`
		AppleDouble *struct {
			Raw  string `json:"raw"`
			Size int    `json:"size"`
			Attr *struct {
				Attrs []struct {
					Name   string `json:"name"`
					Value  string `json:"value"`
					Length int    `json:"length"`
				} `json:"attrs"`
			} `json:"attr"`
			FinderInfo   string `json:"finderInfo"`
			ResourceFork struct {
				Length int `json:"length"`
			} `json:"resourceFork"`
		} `json:"appleDouble"`
	} `json:"Payload"`
}

func loadProbe(t *testing.T) probe {
	t.Helper()
	b, err := os.ReadFile("../../testdata/cli/component-links.probe.json")
	if err != nil {
		t.Fatal("required native probe fixture:", err)
	}
	var p probe
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPkgbuildSidecarsRoundTrip decodes every sidecar pkgbuild wrote and
// re-encodes it to the same bytes.
func TestPkgbuildSidecarsRoundTrip(t *testing.T) {
	p := loadProbe(t)
	n := 0
	for _, e := range p.Payload {
		if e.AppleDouble == nil {
			continue
		}
		n++
		raw, err := base64.StdEncoding.DecodeString(e.AppleDouble.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != e.AppleDouble.Size {
			t.Fatalf("%s: probe raw is %d bytes, size says %d", e.Name, len(raw), e.AppleDouble.Size)
		}
		f, err := Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		if e.AppleDouble.Attr != nil {
			if len(f.Attrs) != len(e.AppleDouble.Attr.Attrs) {
				t.Errorf("%s: %d attrs, probe has %d", e.Name, len(f.Attrs), len(e.AppleDouble.Attr.Attrs))
			}
			for i, a := range e.AppleDouble.Attr.Attrs {
				if i >= len(f.Attrs) {
					break
				}
				want, _ := base64.StdEncoding.DecodeString(a.Value)
				if f.Attrs[i].Name != a.Name || !bytes.Equal(f.Attrs[i].Value, want) {
					t.Errorf("%s: attr %d = %s (%d bytes), probe %s (%d bytes)", e.Name, i, f.Attrs[i].Name, len(f.Attrs[i].Value), a.Name, a.Length)
				}
			}
		}
		if len(f.ResourceFork) != e.AppleDouble.ResourceFork.Length {
			t.Errorf("%s: resource fork %d bytes, probe %d", e.Name, len(f.ResourceFork), e.AppleDouble.ResourceFork.Length)
		}
		if strings.HasPrefix(e.AppleDouble.FinderInfo, "41414141") && f.FinderInfo[0] != 0x41 {
			t.Errorf("%s: Finder info not decoded", e.Name)
		}
		out, err := f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, raw) {
			t.Errorf("%s: re-encoded bytes differ\n got %x\nwant %x", e.Name, out, raw)
		}
		// Through the xattr map and back.
		again := FromXattrs(f.Xattrs())
		out2, _ := again.Encode()
		if !bytes.Equal(out2, raw) {
			t.Errorf("%s: FromXattrs(Xattrs()) changed the bytes", e.Name)
		}
	}
	if n == 0 {
		t.Fatal("probe has no sidecars")
	}
}

func TestGoldenSingleAttr(t *testing.T) {
	// pkgbuild's 163-byte sidecar for one 11-byte com.apple.provenance
	// value; the value itself is host-specific, so only the frame is
	// checked here (the probe test checks whole files).
	f := FromXattrs(map[string][]byte{"com.apple.provenance": make([]byte, 11)})
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 163 {
		t.Fatalf("encoded %d bytes, pkgbuild writes 163", len(b))
	}
	if string(b[84:88]) != "ATTR" || string(b[8:24]) != filler {
		t.Errorf("frame: %x", b[:88])
	}
}

func TestAlignment(t *testing.T) {
	for n := 1; n <= 8; n++ {
		name := strings.Repeat("n", n)
		f := &File{Attrs: []Attr{{Name: name, Value: []byte("v")}}}
		b, err := f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		g, err := Decode(b)
		if err != nil || len(g.Attrs) != 1 || g.Attrs[0].Name != name || string(g.Attrs[0].Value) != "v" {
			t.Errorf("name length %d: %v %+v", n, err, g)
		}
		if (len(b)-120-1)%4 != 0 {
			t.Errorf("name length %d: entry not padded (%d bytes)", n, len(b))
		}
	}
}

func TestEmptyAndErrors(t *testing.T) {
	f := &File{}
	b, _ := f.Encode()
	if len(b) != 120 {
		t.Errorf("empty sidecar is %d bytes", len(b))
	}
	g, err := Decode(b)
	if err != nil || !g.Empty() {
		t.Errorf("empty: %v %+v", err, g)
	}
	if _, err := Decode([]byte("nope")); err != ErrNotAppleDouble {
		t.Errorf("garbage: %v", err)
	}
	big := &File{}
	for range MaxHeader / 16 {
		big.Attrs = append(big.Attrs, Attr{Name: "x"})
	}
	if _, err := big.Encode(); err != ErrTooLarge {
		t.Errorf("too large: %v", err)
	}
	if !IsSidecarName("./a/._b") || IsSidecarName("./a/b") || SidecarName("./a/b") != "./a/._b" {
		t.Error("names")
	}
	if o, ok := OwnerName("./a/._b"); !ok || o != "./a/b" {
		t.Error("owner name")
	}
	if fi := FromXattrs(map[string][]byte{FinderInfoName: bytes.Repeat([]byte{0x41}, 32)}); fi.FinderInfo[31] != 0x41 || len(fi.Attrs) != 0 {
		t.Error("Finder info not lifted")
	}
}
