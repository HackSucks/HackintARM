package decmpfs

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

func TestQueryNativeMetadata(t *testing.T) {
	f, err := os.Open("../../../testdata/appledouble/native/compression-query.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	type query struct {
		Result, Errno int
		Bytes         string
		Guard         bool
	}
	var corpus struct {
		Schema  int
		Sources map[string]string
		Cases   []struct {
			Filesystem, Name              string
			Flags                         uint32
			Attribute, Fork               []byte
			MissingAttribute, MissingFork bool
			Observation                   struct {
				Flags uint32 `json:"initial_flags"`
				Size  uint64 `json:"initial_size"`
				Held  query  `json:"initial_held_query"`
				Path  query  `json:"path_query"`
			}
		}
	}
	if err = json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != 676 {
		t.Fatal("incomplete native query corpus")
	}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../../.."), corpus.Sources)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	if err := captureprovenance.Verify(referenceSources, corpus.Sources); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"scripts/capture-compression-query.go", "internal/testutil/diskimage/attachment.go", "internal/testutil/diskimage/detach.go", "testdata/appledouble/native/compression-query.c", "testdata/appledouble/native/compression-policy.c", "go.mod", "go.sum"} {
		b, err := captureprovenance.ReadSource(referenceSources, corpus.Sources, path)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != corpus.Sources[path] {
			t.Fatalf("stale native query source %s", path)
		}
	}
	for _, c := range corpus.Cases {
		t.Run(fmt.Sprintf("%s/%d/%s", c.Filesystem, c.Flags, c.Name), func(t *testing.T) {
			m := Metadata{Flags: c.Observation.Flags, LogicalSize: c.Observation.Size, ResourceForkSize: -1}
			if !c.MissingAttribute {
				m.Attribute = bytes.NewReader(c.Attribute)
			}
			// Both captured filesystems normalize empty forks to absence.
			if !c.MissingFork && len(c.Fork) != 0 {
				m.ResourceForkSize = int64(len(c.Fork))
			}
			got, err := Query(t.Context(), m)
			if err != nil {
				t.Fatal(err)
			}
			var wire [32]byte
			binary.LittleEndian.PutUint32(wire[:4], got.Type)
			binary.LittleEndian.PutUint32(wire[4:8], got.Overhead)
			binary.LittleEndian.PutUint64(wire[8:16], got.StoredSize)
			binary.LittleEndian.PutUint64(wire[16:24], got.LogicalSize)
			copy(wire[24:], got.AttributeExtension[:])
			for _, native := range []query{c.Observation.Held, c.Observation.Path} {
				if native.Result != 0 || !native.Guard || native.Bytes != hex.EncodeToString(wire[:]) {
					t.Fatalf("native query differs: %x / %+v", wire, native)
				}
				if got.MissingResourceFork != (native.Errno == 93) {
					t.Fatal("missing resource fork status differs")
				}
			}
		})
	}
}

type queryValue struct {
	data   []byte
	size   int64
	err    error
	short  bool
	cancel context.CancelFunc
	reads  int
}

func (v *queryValue) Size() int64 { return v.size }
func (v *queryValue) ReadAt(p []byte, _ int64) (int, error) {
	if len(p) > 24 {
		panic("unbounded query read")
	}
	v.reads++
	if v.cancel != nil {
		v.cancel()
	}
	n := copy(p, v.data)
	if v.short {
		n--
	}
	return n, v.err
}

func TestQueryMetadataFailuresAndBounds(t *testing.T) {
	valid := make([]byte, 24)
	copy(valid, "fpmc")
	binary.LittleEndian.PutUint32(valid[4:], 8)
	binary.LittleEndian.PutUint64(valid[8:], 65537)
	boom := errors.New("source failure")
	for _, c := range []struct {
		name string
		ctx  context.Context
		m    Metadata
		want error
		bad  bool
	}{
		{"nil-context", nil, Metadata{}, nil, true},
		{"bad-fork", t.Context(), Metadata{ResourceForkSize: -2}, nil, true},
		{"missing-attribute", t.Context(), Metadata{Flags: 32}, nil, true},
		{"short-attribute", t.Context(), Metadata{Flags: 32, Attribute: bytes.NewReader(valid[:15])}, nil, true},
		{"negative-size", t.Context(), Metadata{Flags: 32, Attribute: &queryValue{size: -1}}, nil, true},
		{"bad-magic", t.Context(), Metadata{Flags: 32, Attribute: bytes.NewReader(make([]byte, 16))}, nil, true},
		{"read-error", t.Context(), Metadata{Flags: 32, Attribute: &queryValue{size: 24, err: boom}}, boom, true},
		{"short-nil", t.Context(), Metadata{Flags: 32, Attribute: &queryValue{size: 24, data: valid, short: true}}, io.ErrUnexpectedEOF, true},
		{"full-eof", t.Context(), Metadata{Flags: 32, Attribute: &queryValue{size: 24, data: valid, err: io.EOF}}, nil, false},
		{"zero-fork", t.Context(), Metadata{Flags: 32, Attribute: bytes.NewReader(valid)}, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := Query(c.ctx, c.m)
			if (err != nil) != c.bad || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("%+v %v", got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Query(ctx, Metadata{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	v := &queryValue{size: 24, data: valid, cancel: cancel}
	if _, err := Query(ctx, Metadata{Flags: 32, Attribute: v}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	v = &queryValue{size: 1 << 40, data: valid}
	got, err := Query(t.Context(), Metadata{Flags: 32, Attribute: v, ResourceForkSize: 1 << 40})
	if err != nil || got.StoredSize != 2<<40 || got.Overhead != 12 || v.reads != 1 {
		t.Fatalf("bounded large extent: %+v %v reads=%d", got, err, v.reads)
	}
	v = &queryValue{size: 24, err: boom}
	got, err = Query(t.Context(), Metadata{LogicalSize: 1 << 40, Attribute: v})
	if err != nil || got.LogicalSize != 1<<40 || v.reads != 0 {
		t.Fatalf("uncompressed query read attribute: %+v %v", got, err)
	}
}

func FuzzQueryMetadata(f *testing.F) {
	f.Add(uint32(32), uint64(65536), []byte("fpmc\x08\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"), int64(0))
	f.Fuzz(func(t *testing.T, flags uint32, size uint64, attr []byte, fork int64) {
		_, _ = Query(t.Context(), Metadata{Flags: flags, LogicalSize: size, Attribute: bytes.NewReader(attr), ResourceForkSize: fork})
	})
}
