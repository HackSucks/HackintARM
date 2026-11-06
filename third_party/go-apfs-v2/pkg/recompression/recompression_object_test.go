package recompression

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func objectFixture(t *testing.T, flags, volume uint32, values map[string]appledouble.Value) *recompressionObject {
	t.Helper()
	directory := t.TempDir()
	file, e := os.OpenFile(filepath.Join(directory, "logical"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write([]byte("logical payload")); e != nil {
		t.Fatal(e)
	}
	stamp := time.Unix(1234, 567).UTC()
	source := hostdata.StatCopySource{UID: 501, GID: 20, Mode: 0100640, Flags: flags, Times: hostdata.FileTimes{Modify: stamp, Access: stamp}}
	o, e := newRecompressionObject(file, source, values, volume, directory, func() time.Time { return stamp.Add(time.Hour) })
	if e != nil {
		file.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = o.close() })
	return o
}
func objectStream(t *testing.T, o *recompressionObject) *recompressionStream {
	t.Helper()
	input, e := o.open(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	stream, e := input.Duplicate()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = input.Close(); _ = stream.Close() })
	return stream.(*recompressionStream)
}
func objectHeader(kind uint32) *bytes.Reader {
	p := make([]byte, 16)
	copy(p, []byte("fpmc"))
	binary.LittleEndian.PutUint32(p[4:], kind)
	binary.LittleEndian.PutUint64(p[8:], 15)
	return bytes.NewReader(p)
}
func objectValue(t *testing.T, v appledouble.Value) []byte {
	t.Helper()
	if v == nil {
		t.Fatal("missing value")
	}
	p := make([]byte, v.Size())
	n, e := v.ReadAt(p, 0)
	if n != len(p) || e != nil && !errors.Is(e, io.EOF) {
		t.Fatalf("read value %d %v", n, e)
	}
	return p
}
func TestCarrierRecompressionObjectAcquisition(t *testing.T) {
	for _, kind := range []uint32{3, 4, 7, 8, 9, 10, 11, 12, 13, 14} {
		t.Run("type-"+strconv.FormatUint(uint64(kind), 10), func(t *testing.T) {
			values := map[string]appledouble.Value{hostdata.DecmpfsName: objectHeader(kind), hostdata.ResourceForkName: bytes.NewReader([]byte("independent fork")), "user.kept": bytes.NewReader([]byte("kept"))}
			o := objectFixture(t, hostdata.UFCompressed|0x8000, 0, values)
			before := o.metadata.Snapshot().Stat
			input, e := o.open(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer input.Close()
			state, e := input.Snapshot()
			if e != nil {
				t.Fatal(e)
			}
			if state.Size != 15 || state.Stat.Flags != 0x8000 || state.Stat.Mode != before.Mode || state.Stat.UID != before.UID || state.Stat.GID != before.GID || !state.Stat.Times.Modify.Equal(o.now()) || !state.Stat.Times.Access.Equal(before.Times.Access) {
				t.Fatalf("state: %#v", state)
			}
			if _, ok := o.values[hostdata.DecmpfsName]; ok {
				t.Fatal("active compression attribute retained")
			}
			_, fork := o.values[hostdata.ResourceForkName]
			if fork != (kind%2 == 1) {
				t.Fatalf("type %d independent fork presence %v", kind, fork)
			}
			if !bytes.Equal(objectValue(t, o.values["user.kept"]), []byte("kept")) {
				t.Fatal("unrelated attribute changed")
			}
			if values[hostdata.DecmpfsName] == nil || values[hostdata.ResourceForkName] == nil {
				t.Fatal("caller map mutated")
			}
			if _, e = o.open(context.Background()); !errors.Is(e, metatransport.ErrInvalid) {
				t.Fatal(e)
			}
		})
	}
	t.Run("inactive opaque", func(t *testing.T) {
		o := objectFixture(t, 0, 0, map[string]appledouble.Value{hostdata.DecmpfsName: bytes.NewReader([]byte("opaque"))})
		before := o.metadata.Snapshot()
		input, e := o.open(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		defer input.Close()
		if !reflect.DeepEqual(before, o.metadata.Snapshot()) || string(objectValue(t, o.values[hostdata.DecmpfsName])) != "opaque" {
			t.Fatal("inactive metadata modified")
		}
	})
	t.Run("invalid active", func(t *testing.T) {
		o := objectFixture(t, hostdata.UFCompressed, 0, map[string]appledouble.Value{hostdata.DecmpfsName: bytes.NewReader([]byte("bad"))})
		before := o.metadata.Snapshot()
		if _, e := o.open(context.Background()); e == nil {
			t.Fatal("accepted malformed active attribute")
		}
		if o.opened || !reflect.DeepEqual(before, o.metadata.Snapshot()) {
			t.Fatal("failed open changed state")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		o := objectFixture(t, 0, 0, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, e := o.open(ctx); !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
		if o.opened {
			t.Fatal("cancelled open acquired object")
		}
	})
	t.Run("closed", func(t *testing.T) {
		o := objectFixture(t, 0, 0, nil)
		if e := o.close(); e != nil {
			t.Fatal(e)
		}
		if _, e := o.open(context.Background()); !errors.Is(e, metatransport.ErrInvalid) {
			t.Fatal(e)
		}
		if e := o.close(); e != nil {
			t.Fatal(e)
		}
		if _, e := o.outputValues(); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
	})
}
func TestCarrierRecompressionObjectStream(t *testing.T) {
	for _, volume := range []uint32{0, 0x10000000} {
		t.Run("volume-"+strconv.FormatUint(uint64(volume), 16), func(t *testing.T) {
			o := objectFixture(t, 0x8000, volume, map[string]appledouble.Value{hostdata.ResourceForkName: bytes.NewReader([]byte("fork"))})
			s := objectStream(t, o)
			before := o.metadata.Snapshot().Stat
			if e := s.ProbeWrite(); e != nil {
				t.Fatal(e)
			}
			if got, e := s.VolumeFlags(); got != volume || e != nil {
				t.Fatal(got, e)
			}
			p := make([]byte, 20)
			n, e := s.ReadAt(p, 0)
			if n != 15 || !errors.Is(e, io.EOF) || string(p[:n]) != "logical payload" {
				t.Fatal(n, e, string(p[:n]))
			}
			access := o.metadata.Snapshot().Stat.Times.Access
			want := o.now()
			if volume != 0 {
				want = before.Times.Access
			}
			if !access.Equal(want) {
				t.Fatal(access, want)
			}
			if n, e = s.ReadAt(p, 100); n != 0 || !errors.Is(e, io.EOF) {
				t.Fatal(n, e)
			}
			if flags, e := s.ReadFlags(); flags != 0x8000 || e != nil {
				t.Fatal(flags, e)
			}
			if actual, e := s.CompareAndSwapFlags(0, 7); actual != 0x8000 || e != nil {
				t.Fatal(actual, e)
			}
			if actual, e := s.CompareAndSwapFlags(0x8000, 9); actual != 0x8000 || e != nil {
				t.Fatal(actual, e)
			}
			if e = s.Chmod(0701); e != nil {
				t.Fatal(e)
			}
			modify, atime := time.Unix(3000, 1), time.Unix(4000, 2)
			if e = s.SetCompressionTimes(modify, atime); e != nil {
				t.Fatal(e)
			}
			state, e := s.Snapshot()
			if e != nil || state.Stat.Mode != 0100701 || state.Stat.Flags != 9 || !state.Stat.Times.Modify.Equal(modify) || !state.Stat.Times.Access.Equal(atime) {
				t.Fatal(state, e)
			}
			attr := []byte("owned attribute")
			if e = s.SetCompressionAttribute(attr); e != nil {
				t.Fatal(e)
			}
			attr[0] = 'X'
			if string(objectValue(t, o.values[hostdata.DecmpfsName])) != "owned attribute" {
				t.Fatal("attribute ownership")
			}
			if size, e := s.CompressionForkSize(); size != 4 || e != nil {
				t.Fatal(size, e)
			}
			delete(o.values, hostdata.ResourceForkName)
			if size, e := s.CompressionForkSize(); size != 0 || e != nil {
				t.Fatal(size, e)
			}
			if e = s.TruncateData(1); !errors.Is(e, metatransport.ErrInvalid) || o.truncated {
				t.Fatal(e)
			}
			if e = s.TruncateData(0); e != nil || !o.truncated {
				t.Fatal(e)
			}
			if info, e := o.data.Stat(); e != nil || info.Size() != 15 {
				t.Fatal("logical payload destructively truncated", info, e)
			}
			if e = s.SyncData(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestCarrierRecompressionObjectClosedLeases(t *testing.T) {
	for _, closeObject := range []bool{false, true} {
		t.Run(map[bool]string{false: "lease", true: "object"}[closeObject], func(t *testing.T) {
			o := objectFixture(t, 0, 0, nil)
			s := objectStream(t, o)
			if closeObject {
				if e := o.close(); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := s.Close(); e != nil {
					t.Fatal(e)
				}
				if e := s.Close(); !errors.Is(e, os.ErrClosed) {
					t.Fatal(e)
				}
			}
			requireClosed := func(e error) {
				t.Helper()
				if !errors.Is(e, os.ErrClosed) {
					t.Fatal(e)
				}
			}
			_, e := s.Snapshot()
			requireClosed(e)
			requireClosed(s.ProbeWrite())
			_, e = s.Duplicate()
			requireClosed(e)
			_, e = s.ReadAt(make([]byte, 1), 0)
			requireClosed(e)
			_, e = s.VolumeFlags()
			requireClosed(e)
			_, e = s.ReadFlags()
			requireClosed(e)
			_, e = s.CompareAndSwapFlags(0, 1)
			requireClosed(e)
			requireClosed(s.SetCompressionAttribute(nil))
			requireClosed(s.Chmod(0600))
			requireClosed(s.TruncateData(0))
			requireClosed(s.SyncData())
			requireClosed(s.SetCompressionTimes(time.Time{}, time.Time{}))
			_, e = s.CompressionForkSize()
			requireClosed(e)
			_, e = s.OpenCompressionFork()
			requireClosed(e)
		})
	}
	t.Run("closed backing", func(t *testing.T) {
		o := objectFixture(t, 0, 0, nil)
		s := objectStream(t, o)
		if e := o.data.Close(); e != nil {
			t.Fatal(e)
		}
		statCause := closedFileStatCause(t, o.data)
		if _, e := s.Snapshot(); !errors.Is(e, statCause) {
			t.Fatal(e)
		}
		if e := s.SyncData(); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
		if e := o.close(); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
	})
}
func TestCarrierRecompressionObjectFork(t *testing.T) {
	t.Run("write and export", func(t *testing.T) {
		o := objectFixture(t, 0, 0, nil)
		s := objectStream(t, o)
		f, e := s.OpenCompressionFork()
		if e != nil {
			t.Fatal(e)
		}
		if e = f.Sync(); e != nil {
			t.Fatal(e)
		}
		if n, e := f.WriteAt([]byte("tail"), 4); n != 4 || e != nil {
			t.Fatal(n, e)
		}
		if n, e := f.WriteAt([]byte("head"), 0); n != 4 || e != nil {
			t.Fatal(n, e)
		}
		if e = f.Sync(); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
		if _, e = f.WriteAt(nil, 0); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
		if e = f.Sync(); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
		values, e := o.outputValues()
		if e != nil || string(objectValue(t, values[hostdata.ResourceForkName])) != "headtail" {
			t.Fatal(values, e)
		}
		delete(values, hostdata.ResourceForkName)
		if o.values[hostdata.ResourceForkName] == nil {
			t.Fatal("output map aliases object")
		}
		reader := o.readers[0]
		if e = o.close(); e != nil {
			t.Fatal(e)
		}
		requireFileClosed(t, reader)
	})
	t.Run("empty export", func(t *testing.T) {
		o := objectFixture(t, 0, 0, map[string]appledouble.Value{hostdata.ResourceForkName: bytes.NewReader([]byte("old"))})
		if e := os.WriteFile(filepath.Join(o.directory, "resource-fork"), nil, 0600); e != nil {
			t.Fatal(e)
		}
		values, e := o.outputValues()
		if e != nil || values[hostdata.ResourceForkName] != nil {
			t.Fatal(values, e)
		}
	})
	t.Run("absent export", func(t *testing.T) {
		o := objectFixture(t, 0, 0, map[string]appledouble.Value{"kept": bytes.NewReader([]byte("v"))})
		values, e := o.outputValues()
		if e != nil || string(objectValue(t, values["kept"])) != "v" {
			t.Fatal(values, e)
		}
	})
	t.Run("create failure", func(t *testing.T) {
		o := objectFixture(t, 0, 0, nil)
		o.directory = filepath.Join(o.directory, "missing")
		s := objectStream(t, o)
		f, e := s.OpenCompressionFork()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.WriteAt([]byte("x"), 0); !errors.Is(e, os.ErrNotExist) {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("export failure", func(t *testing.T) {
		o := objectFixture(t, 0, 0, nil)
		o.directory += "\x00invalid"
		if _, e := o.outputValues(); !errors.Is(e, syscall.EINVAL) {
			t.Fatal("accepted invalid staging directory")
		}
	})
	t.Run("owner closes active fork", func(t *testing.T) {
		o := objectFixture(t, 0, 0, nil)
		s := objectStream(t, o)
		f, e := s.OpenCompressionFork()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.WriteAt([]byte("x"), 0); e != nil {
			t.Fatal(e)
		}
		if e = o.close(); e != nil {
			t.Fatal(e)
		}
		if _, e = f.WriteAt(nil, 0); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
		if e = f.Sync(); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
		if e = f.Close(); !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
	})
}

type negativeObjectValue struct{}

func (negativeObjectValue) Size() int64                       { return -1 }
func (negativeObjectValue) ReadAt([]byte, int64) (int, error) { return 0, io.EOF }
func TestCarrierRecompressionObjectInvalid(t *testing.T) {
	o := objectFixture(t, 0, 0, nil)
	source := o.metadata.Snapshot().Stat
	for _, values := range []map[string]appledouble.Value{{"nil": nil}, {"negative": negativeObjectValue{}}} {
		if _, e := newRecompressionObject(o.data, source, values, 0, o.directory, o.now); !errors.Is(e, metatransport.ErrInvalid) {
			t.Fatal(e)
		}
	}
	if _, e := newRecompressionObject(nil, source, nil, 0, o.directory, o.now); !errors.Is(e, metatransport.ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := newRecompressionObject(o.data, source, nil, 0, o.directory, nil); !errors.Is(e, metatransport.ErrInvalid) {
		t.Fatal(e)
	}
}
func TestCarrierRecompressionStageLifecycle(t *testing.T) {
	directory := t.TempDir()
	stage, e := newRecompressionStage(context.Background(), directory)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = stage.WriteAt([]byte("encoded"), 0); e != nil {
		t.Fatal(e)
	}
	p := make([]byte, 7)
	if _, e = stage.ReadAt(p, 0); e != nil || string(p) != "encoded" {
		t.Fatal(string(p), e)
	}
	if e = stage.Close(); e != nil {
		t.Fatal(e)
	}
	files, e := os.ReadDir(directory)
	if e != nil || len(files) != 0 {
		t.Fatal(files, e)
	}
	if e = stage.Close(); !errors.Is(e, os.ErrClosed) || !errors.Is(e, os.ErrNotExist) {
		t.Fatal("must retain both cleanup failures", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = newRecompressionStage(ctx, directory); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = newRecompressionStage(context.Background(), filepath.Join(directory, "missing")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}

func TestCarrierRecompressionObjectPartialForkFailure(t *testing.T) {
	o := objectFixture(t, 0, 0, nil)
	stream := objectStream(t, o)
	fork, err := stream.OpenCompressionFork()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := fork.WriteAt([]byte("retained prefix"), 0); n != 15 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := fork.WriteAt([]byte("not written"), -1); n != 0 || err == nil {
		t.Fatal("invalid offset write succeeded", n, err)
	}
	if err := fork.Close(); err != nil {
		t.Fatal(err)
	}
	values, err := o.outputValues()
	if err != nil || string(objectValue(t, values[hostdata.ResourceForkName])) != "retained prefix" {
		t.Fatal("partial output lost", values, err)
	}
}

func TestCarrierRecompressionObjectReadOnlyFork(t *testing.T) {
	o := objectFixture(t, 0, 0, nil)
	stream := objectStream(t, o)
	path := filepath.Join(o.directory, "resource-fork")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise a write failure on an actual read-only descriptor on every OS;
	// mode bits alone would not reliably fail under root or Windows ACLs.
	o.forkFile = file
	fork, err := stream.OpenCompressionFork()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := fork.WriteAt([]byte("replacement"), 0); n != 0 || err == nil {
		t.Fatal("read-only descriptor accepted write", n, err)
	}
	if err := fork.Close(); err != nil {
		t.Fatal(err)
	}
	values, err := o.outputValues()
	if err != nil || string(objectValue(t, values[hostdata.ResourceForkName])) != "unchanged" {
		t.Fatal("failed write changed output", values, err)
	}
}

func TestCarrierRecompressionObjectCloseContinuesAfterFailure(t *testing.T) {
	o := objectFixture(t, 0, 0, nil)
	stream := objectStream(t, o)
	fork, err := stream.OpenCompressionFork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fork.WriteAt([]byte("fork"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.outputValues(); err != nil {
		t.Fatal(err)
	}
	reader := o.readers[0]
	if err := o.forkFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("lost fork close failure", err)
	}
	requireFileClosed(t, reader)
	requireFileClosed(t, o.data)
}

func TestCarrierRecompressionObjectAuthorization(t *testing.T) {
	for _, readonly := range []bool{false, true} {
		t.Run(fmt.Sprintf("read-only-volume-%v", readonly), func(t *testing.T) {
			o := objectFixture(t, 0, 0, map[string]appledouble.Value{"kept": bytes.NewReader([]byte("metadata"))})
			stream := objectStream(t, o)
			o.access = &recompressionAccess{profile: osversion.MacOS27, authority: Authority{UID: 502, Groups: []uint32{20}}}
			if readonly {
				o.access.volume = 1
			}
			before := o.stat()
			checks := []struct {
				name       string
				run        func() error
				permission error
			}{
				{"flags", func() error { _, e := stream.CompareAndSwapFlags(0, 32); return e }, syscall.EPERM},
				{"attribute", func() error { return stream.SetCompressionAttribute([]byte("should not persist")) }, syscall.EACCES},
				{"mode", func() error { return stream.Chmod(0700) }, syscall.EPERM},
				{"times", func() error { return stream.SetCompressionTimes(time.Unix(9000, 0), time.Unix(9001, 0)) }, syscall.EPERM},
				{"fork", func() error {
					fork, e := stream.OpenCompressionFork()
					if fork != nil {
						fork.Close()
						t.Fatal("denied fork acquired handle")
					}
					return e
				}, syscall.EACCES},
			}
			for _, check := range checks {
				t.Run(check.name, func(t *testing.T) {
					e := check.run()
					want := check.permission
					if readonly && check.name != "times" {
						want = syscall.EROFS
					}
					if !errors.Is(e, want) {
						t.Fatalf("expected %v, got %v", want, e)
					}
					if check.name == "attribute" && errors.Is(e, hostdata.ErrCompressionAttributeAccess) == readonly {
						t.Fatal("attribute denial classification", e)
					}
					if o.stat() != before || o.truncated || o.changeChanged || o.forkFile != nil || o.values[hostdata.DecmpfsName] != nil || len(o.values) != 1 {
						t.Fatal("denied operation changed foreign state")
					}
				})
			}
		})
	}
	t.Run("denied acquisition", func(t *testing.T) {
		o := objectFixture(t, hostdata.UFCompressed, 0, map[string]appledouble.Value{hostdata.DecmpfsName: objectHeader(7)})
		o.access = &recompressionAccess{profile: osversion.MacOS27, authority: Authority{UID: 502}}
		before := o.stat()
		if _, e := o.open(context.Background()); !errors.Is(e, syscall.EACCES) {
			t.Fatal(e)
		}
		if o.opened || o.changeChanged || o.stat() != before || o.values[hostdata.DecmpfsName] == nil {
			t.Fatal("denied acquisition materialized compressed source")
		}
	})
	t.Run("invalid active baseline", func(t *testing.T) {
		o := objectFixture(t, hostdata.UFCompressed, 0, map[string]appledouble.Value{hostdata.DecmpfsName: bytes.NewReader(storageRaw([]byte("logical payload")))})
		baseline := digest([]byte("wrong baseline!"))
		o.baseline = &baseline
		before := o.stat()
		if _, e := o.open(context.Background()); !errors.Is(e, metatransport.ErrCorrupt) {
			t.Fatal(e)
		}
		if o.opened || o.changeChanged || o.stat() != before || o.values[hostdata.DecmpfsName] == nil {
			t.Fatal("invalid compressed baseline changed state")
		}
	})
	t.Run("authorized mode and times", func(t *testing.T) {
		o := objectFixture(t, 0, 0, nil)
		stream := objectStream(t, o)
		o.access = &recompressionAccess{profile: osversion.MacOS27, authority: Authority{UID: 501, Groups: []uint32{20}}}
		if e := stream.Chmod(0600); e != nil {
			t.Fatal(e)
		}
		if !o.changeChanged || !o.stat().Times.Change.Equal(o.now()) || o.stat().Mode != 0100600 {
			t.Fatal("successful mode mutation missing change time")
		}
		if e := stream.TruncateData(0); e != nil {
			t.Fatal(e)
		}
		if !o.stat().Times.Modify.Equal(o.now()) || !o.stat().Times.Change.Equal(o.now()) {
			t.Fatal("truncation did not update native modification and change times")
		}
	})
}

func TestCarrierRecompressionObjectHeldTruncate(t *testing.T) {
	for _, tc := range []struct {
		name          string
		flags, volume uint32
		want          error
	}{
		{name: "held write capability"},
		{name: "read-only volume", volume: 1, want: syscall.EROFS},
		{name: "immutable inode retains held capability", flags: 2},
		{name: "append-only inode", flags: 4, want: syscall.EPERM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := objectFixture(t, 0, 0, nil)
			stream := objectStream(t, o)
			// The data descriptor was admitted for writing before metadata changed.
			// ftruncate retains it across immutable changes; append and mount state still apply.
			if e := o.metadata.Chmod(0); e != nil {
				t.Fatal(e)
			}
			if e := o.metadata.Chflags(tc.flags); e != nil {
				t.Fatal(e)
			}
			o.access = &recompressionAccess{profile: osversion.MacOS27, authority: Authority{UID: 501, Groups: []uint32{20}}, volume: tc.volume}
			before := o.stat()
			e := stream.TruncateData(0)
			if !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
			if tc.want != nil {
				if o.truncated || o.changeChanged || o.stat() != before {
					t.Fatal("denied held truncation mutated state")
				}
			} else {
				if !o.truncated || !o.changeChanged || !o.stat().Times.Modify.Equal(o.now()) {
					t.Fatal("held write capability lost")
				}
			}
		})
	}
}

func TestRecompressionObjectLegacyLZ4Acquisition(t *testing.T) {
	for _, profile := range []osversion.MacOSProfile{osversion.MacOS15, osversion.MacOS26} {
		for _, kind := range []uint32{15, 16} {
			for _, active := range []bool{false, true} {
				t.Run(fmt.Sprintf("profile-%d/type-%d/active-%t", profile, kind, active), func(t *testing.T) {
					flags := uint32(0x8000)
					if active {
						flags |= hostdata.UFCompressed
					}
					values := map[string]appledouble.Value{
						hostdata.DecmpfsName:      objectHeader(kind),
						hostdata.ResourceForkName: bytes.NewReader([]byte("retained fork")),
						"user.kept":               bytes.NewReader([]byte("retained attribute")),
					}
					o := objectFixture(t, flags, 0, values)
					o.access = &recompressionAccess{profile: profile, authority: Authority{UID: 501, Groups: []uint32{20}}}
					before := o.metadata.Snapshot()
					input, err := o.open(t.Context())
					if active {
						if !errors.Is(err, syscall.ENOTSUP) || input != nil || o.opened {
							t.Fatalf("legacy target active LZ4 acquisition: input=%v opened=%t err=%v", input, o.opened, err)
						}
					} else {
						if err != nil || input == nil || !o.opened {
							t.Fatalf("inactive LZ4 acquisition: input=%v opened=%t err=%v", input, o.opened, err)
						}
						if err := input.Close(); err != nil {
							t.Fatal(err)
						}
					}
					if !reflect.DeepEqual(before, o.metadata.Snapshot()) || len(o.values) != len(values) {
						t.Fatal("acquisition changed retained metadata")
					}
					for name, original := range values {
						if !o.retained[name] || !bytes.Equal(objectValue(t, o.values[name]), objectValue(t, original)) {
							t.Fatalf("acquisition changed retained %s", name)
						}
					}
					data := make([]byte, len("logical payload"))
					if n, err := o.data.ReadAt(data, 0); n != len(data) || err != nil || string(data) != "logical payload" {
						t.Fatalf("acquisition changed logical payload: %q %d %v", data, n, err)
					}
				})
			}
		}
	}
}

func TestRecompressionObjectLegacyTypeRead(t *testing.T) {
	sentinel := errors.New("compression type read failure")
	for _, tc := range []struct {
		name string
		n    int
		err  error
		want error
	}{
		{"success", 4, nil, nil},
		{"full read with EOF", 4, io.EOF, nil},
		{"short read", 3, nil, io.ErrUnexpectedEOF},
		{"read failure", 0, sentinel, sentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := objectHeader(3)
			value := &storageObservedValue{Value: base, read: func(p []byte, at int64) (int, error) {
				if at == 4 {
					if _, err := base.ReadAt(p[:tc.n], at); err != nil {
						t.Fatal(err)
					}
					return tc.n, tc.err
				}
				return base.ReadAt(p, at)
			}}
			o := objectFixture(t, hostdata.UFCompressed, 0, map[string]appledouble.Value{hostdata.DecmpfsName: value})
			o.access = &recompressionAccess{profile: osversion.MacOS15, authority: Authority{UID: 501, Groups: []uint32{20}}}
			before := o.metadata.Snapshot()
			input, err := o.open(t.Context())
			if !errors.Is(err, tc.want) {
				t.Fatalf("type read error %v, want %v", err, tc.want)
			}
			if tc.want != nil {
				if input != nil || o.opened || !reflect.DeepEqual(before, o.metadata.Snapshot()) || o.values[hostdata.DecmpfsName] != value || !o.retained[hostdata.DecmpfsName] {
					t.Fatal("failed type read changed acquisition state")
				}
				return
			}
			if input == nil || !o.opened || o.stat().Flags&hostdata.UFCompressed != 0 || len(o.values) != 0 || len(o.retained) != 0 {
				t.Fatal("supported compression was not materialized")
			}
			if err := input.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
