package appledouble

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestFilesystemEncodingNativeCopy(t *testing.T) {
	path := os.Getenv("APFS_REPLACEMENT_FILESYSTEM_CORPUS")
	if path == "" {
		path = "../../testdata/appledouble/native/replacement-filesystem-macos27/cases.json.gz"
	}
	file, err := os.Open(path)

	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var cases []struct {
		Filesystem, Profile string
		Input, Native       []byte
		Errno               int
	}
	if err = json.NewDecoder(z).Decode(&cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 220 {
		t.Fatal("incomplete native copy corpus", len(cases))
	}
	negative := 0
	for _, c := range cases {
		t.Run(c.Filesystem+"/"+c.Profile, func(t *testing.T) {
			f, e := DecodeFilesystemStream(t.Context(), bytes.NewReader(c.Input), DefaultStreamLimits())
			if e != nil {
				t.Fatal(e)
			}
			if c.Errno != 0 {
				// copyfile retains the failed fork write error while continuing later
				// attributes. Validate that complete observed partial carrier too.
				negative++
				if c.Errno != 22 || f.ResourceFork == nil || f.ResourceFork.Size() < 1 || f.ResourceFork.Size() > 285 {
					t.Fatal("unexpected native failure", c.Errno)
				}
				f.ResourceFork = nil
			}
			var encoded bytes.Buffer
			n, e := f.EncodeFilesystemTo(t.Context(), &encoded, DefaultStreamLimits())
			if e != nil || n != int64(len(c.Native)) || !bytes.Equal(encoded.Bytes(), c.Native) {
				t.Fatalf("native carrier differs: count=%d err=%v", n, e)
			}
		})
	}
	expectedFailures := 100
	if raw := os.Getenv("APFS_REPLACEMENT_FILESYSTEM_PROFILE"); raw != "" {
		profile, err := strconv.Atoi(raw)
		if err != nil || (profile != 15 && profile != 26 && profile != 27) {
			t.Fatal("invalid native profile", raw, err)
		}
		if profile == 15 {
			expectedFailures = 0
		}
	}
	if negative != expectedFailures {
		t.Fatal("lost native failure outcomes", negative)
	}
}

func TestFilesystemEncodingValidation(t *testing.T) {
	value := func(n int64) Value {
		return streamTestValue{size: n, read: func(p []byte, _ int64) (int, error) { clear(p); return len(p), nil }}
	}
	inputs := []*StreamFile{
		nil, {Attrs: make([]StreamAttr, 5000)},
		{Attrs: []StreamAttr{{Name: ""}}}, {Attrs: []StreamAttr{{Name: strings.Repeat("n", 128)}}},
		{Attrs: []StreamAttr{{Name: "nul\x00name"}}}, {Attrs: []StreamAttr{{Name: "\xff"}}},
		{Attrs: []StreamAttr{{Name: FinderInfoName}}}, {Attrs: []StreamAttr{{Name: ResourceForkName}}},
		{Attrs: []StreamAttr{{Name: "a"}, {Name: "a"}}},
		{Attrs: []StreamAttr{{Name: "a", Value: value(-1)}}},
		{Attrs: []StreamAttr{{Name: "a", Value: value(math.MaxInt32 + 1)}}},
		{Attrs: []StreamAttr{{Name: "a", Value: value(math.MaxInt32)}, {Name: "b", Value: value(math.MaxInt32)}}},
		{Attrs: []StreamAttr{{Name: "a", Value: value(math.MaxInt32)}, {Name: "b", Value: value(math.MaxInt32 - 400)}}},
		{ResourceFork: value(-1)}, {ResourceFork: value(math.MaxUint32 + 1)},
	}
	large := &StreamFile{}
	for i := 0; i < 512; i++ {
		large.Attrs = append(large.Attrs, StreamAttr{Name: strings.Repeat("n", 120) + string(rune(0x100+i))})
	}
	inputs = append(inputs, large)
	for _, f := range inputs {
		wrote := false
		reject := streamTestWriter(func([]byte) (int, error) { wrote = true; return 0, io.ErrClosedPipe })
		if n, e := f.EncodeFilesystemTo(t.Context(), reject, DefaultStreamLimits()); e == nil || n != 0 || wrote {
			t.Fatalf("invalid metadata accepted or wrote output: %d %v", n, e)
		}
	}
	f := &StreamFile{Attrs: []StreamAttr{{Name: "a", Value: value(4)}}}
	if _, e := f.EncodeFilesystemTo(t.Context(), nil, DefaultStreamLimits()); e == nil {
		t.Fatal("nil writer accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := f.EncodeFilesystemTo(ctx, io.Discard, DefaultStreamLimits()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, limits := range []StreamLimits{{MaxFileBytes: 4095, MaxValueBytes: 100, MaxTotalValueBytes: 100}, {MaxFileBytes: 8192, MaxValueBytes: 3, MaxTotalValueBytes: 100}, {MaxFileBytes: 8192, MaxValueBytes: 100, MaxTotalValueBytes: 3}} {
		if _, e := f.EncodeFilesystemTo(t.Context(), io.Discard, limits); !errors.Is(e, ErrStreamBudget) {
			t.Fatal(e)
		}
	}
	f = &StreamFile{ResourceFork: value(4)}
	if _, e := f.EncodeFilesystemTo(t.Context(), io.Discard, StreamLimits{MaxFileBytes: 8192, MaxValueBytes: 3, MaxTotalValueBytes: 100}); !errors.Is(e, ErrStreamBudget) {
		t.Fatal(e)
	}
	if n, e := (&StreamFile{}).EncodeFilesystemTo(t.Context(), io.Discard, DefaultStreamLimits()); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := (&StreamFile{FinderInfo: [32]byte{1}}).EncodeFilesystemTo(t.Context(), io.Discard, DefaultStreamLimits()); n != 4096 || e != nil {
		t.Fatal(n, e)
	}
}

func TestFilesystemEncodingIOFailures(t *testing.T) {
	sentinel := io.ErrClosedPipe
	run := func(failAt int, cancelAt int) (int, error) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		calls := 0
		operation := func() error {
			calls++
			if calls == cancelAt {
				cancel()
			}
			if calls == failAt {
				return sentinel
			}
			return nil
		}
		value := func(n int64) Value {
			return streamTestValue{size: n, read: func(p []byte, _ int64) (int, error) {
				if e := operation(); e != nil {
					return 0, e
				}
				clear(p)
				return len(p), nil
			}}
		}
		f := &StreamFile{Attrs: []StreamAttr{{Name: "com.example.a", Value: value(65500)}, {Name: "com.example.b", Value: value(4000)}, {Name: "c", Value: value(0)}}, ResourceFork: value(65537)}
		writer := streamTestWriter(func(p []byte) (int, error) {
			if e := operation(); e != nil {
				return 0, e
			}
			return len(p), nil
		})
		_, e := f.EncodeFilesystemTo(ctx, writer, DefaultStreamLimits())
		return calls, e
	}
	count, err := run(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= count; i++ {
		if _, e := run(i, 0); !errors.Is(e, sentinel) {
			t.Fatalf("IO boundary %d: %v", i, e)
		}
		if _, e := run(0, i); !errors.Is(e, context.Canceled) {
			t.Fatalf("cancel boundary %d: %v", i, e)
		}
	}
	f := &StreamFile{Attrs: []StreamAttr{{Name: "a", Value: bytes.NewReader([]byte("value"))}}}
	if _, e := f.EncodeFilesystemTo(t.Context(), streamTestWriter(func([]byte) (int, error) { return 0, nil }), DefaultStreamLimits()); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
}
