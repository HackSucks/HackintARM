package recompression

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func carrierRecompressionFixture(t *testing.T) (*metatransport.Store, string, string, metatransport.Record, Options) {
	t.Helper()
	s, p, m := fixture(t)
	plain := bytes.Repeat([]byte("abcd"), 16384)
	if err := os.WriteFile(filepath.Join(p, "file"), plain, 0600); err != nil {
		t.Fatal(err)
	}
	mode, flags, uid, gid := uint32(0100644), uint32(0), uint32(501), uint32(20)
	modify, access := time.Unix(1600000000, 987654321).UTC(), time.Unix(1550000000, 345678901).UTC()
	birth, change := time.Unix(1500000000, 0).UTC(), time.Unix(1650000000, 0).UTC()
	ref := digest(plain)
	r := metatransport.Record{Original: "file", Materialized: "file", Kind: "file", MaterializedKind: "file", Payload: &ref, Darwin: metatransport.DarwinState{UID: &uid, GID: &gid, Mode: &mode, Flags: &flags, Modify: &modify, Access: &access, Birth: &birth, Change: &change}}
	r.Attributes = []metatransport.Attribute{{Name: "user.retained", Value: mustBlob(t, s, []byte("retained attribute"))}}
	if err := s.Commit(t.Context(), metatransport.Manifest{Version: 1, Records: []metatransport.Record{r}}, 0); err != nil {
		t.Fatal(err)
	}
	opts := Options{Target: osversion.Version{Major: 27}, Authority: &Authority{UID: 501, Groups: []uint32{20}}, Volume: &Volume{Filesystem: "apfs"}, TemporaryDirectory: t.TempDir(), Clock: func() time.Time { return time.Unix(1700000000, 123456789).UTC() }}
	return s, p, m, r, opts
}
func checkRecompressionCleanup(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("private staging leak", entries, err)
	}
}
func TestCarrierRecompressionPublication(t *testing.T) {
	for _, kind := range []uint32{0, 3, 7, 9, 11, 13} {
		for _, fork := range []bool{false, true} {
			t.Run(string(rune('A'+kind))+map[bool]string{false: "inline", true: "fork"}[fork], func(t *testing.T) {
				s, p, _, r, o := carrierRecompressionFixture(t)
				o.Encoding = decmpfs.EncodeOptions{Type: kind, ResourceForkOnly: fork}
				got, err := RecompressRecord(t.Context(), s, "file", 1, o)
				if err != nil || !got.Published || got.Generation != 2 || !got.Operation.Accepted {
					t.Fatal(got, err)
				}
				m, err := s.Load(t.Context())
				if err != nil || m.Generation != 2 || !reflect.DeepEqual(m.Records[0], got.Record) {
					t.Fatal(m, got, err)
				}
				if err = s.VerifyPayload(t.Context(), got.Record); err != nil {
					t.Fatal(err)
				}
				plain, err := os.ReadFile(filepath.Join(p, "file"))
				if err != nil || digest(plain) != *r.Payload {
					t.Fatal("materialized data changed", err)
				}
				attrs, err := s.ReadRecordAttributes(t.Context(), got.Record, 1<<20)
				if err != nil || string(attrs["user.retained"]) != "retained attribute" {
					t.Fatal(attrs, err)
				}
				if *got.Record.Darwin.Flags&hostdata.UFCompressed != 0 {
					values, err := s.BorrowRecordAttributes(t.Context(), got.Record)
					if err != nil {
						t.Fatal(err)
					}
					if err = validateRecompressionStorage(t.Context(), values, *r.Payload); err != nil {
						t.Fatal(err)
					}
					if !got.Record.Darwin.Modify.Equal(r.Darwin.Modify.Truncate(time.Microsecond)) || !got.Record.Darwin.Access.Equal(r.Darwin.Access.Truncate(time.Microsecond)) {
						t.Fatal("restoration mismatch", got.Record.Darwin)
					}
				}
				checkRecompressionCleanup(t, o.TemporaryDirectory)
			})
		}
	}
}
func TestCarrierRecompressionPreflight(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*metatransport.Store, *Options)
		want error
	}{
		{"target", func(_ *metatransport.Store, o *Options) { o.Target = osversion.Version{} }, osversion.ErrMacOSProfile},
		{"volume", func(_ *metatransport.Store, o *Options) { o.Volume = nil }, metatransport.ErrInvalid},
		{"filesystem", func(_ *metatransport.Store, o *Options) { o.Volume.Filesystem = "ntfs" }, metatransport.ErrInvalid},
		{"authority", func(_ *metatransport.Store, o *Options) { o.Authority = nil }, ErrAuthority},
		{"stage-parent", func(_ *metatransport.Store, o *Options) {
			o.TemporaryDirectory = filepath.Join(o.TemporaryDirectory, "missing")
		}, fs.ErrNotExist},
		{"closed", func(s *metatransport.Store, _ *Options) {
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		}, os.ErrClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _, _, o := carrierRecompressionFixture(t)
			tc.edit(s, &o)
			r, err := RecompressRecord(t.Context(), s, "file", 1, o)
			if !errors.Is(err, tc.want) || r.Published {
				t.Fatal(r, err)
			}
		})
	}
	s, _, _, _, o := carrierRecompressionFixture(t)
	if _, err := RecompressRecord(t.Context(), s, "file", 0, o); !errors.Is(err, metatransport.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := RecompressRecord(t.Context(), s, "missing", 1, o); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := RecompressRecord(ctx, s, "file", 1, o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestCarrierRecompressionRecordValidation(t *testing.T) {
	for _, change := range []func(*metatransport.Record){
		func(r *metatransport.Record) { r.Darwin.Mode = nil }, func(r *metatransport.Record) { r.Darwin.Flags = nil }, func(r *metatransport.Record) { r.Darwin.Modify = nil }, func(r *metatransport.Record) { r.Darwin.Access = nil }, func(r *metatransport.Record) { r.Darwin.UID = nil }, func(r *metatransport.Record) { r.Darwin.GID = nil }, func(r *metatransport.Record) { n := uint32(040755); r.Darwin.Mode = &n },
	} {
		s, _, _, r, o := carrierRecompressionFixture(t)
		change(&r)
		if err := s.Commit(t.Context(), metatransport.Manifest{Version: 1, Generation: 1, Records: []metatransport.Record{r}}, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := RecompressRecord(t.Context(), s, "file", 2, o); !errors.Is(err, metatransport.ErrInvalid) {
			t.Fatal(err)
		}
	}
}
func TestCarrierRecompressionEditedAndActive(t *testing.T) {
	s, p, _, _, o := carrierRecompressionFixture(t)
	first, err := RecompressRecord(t.Context(), s, "file", 1, o)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Repeat([]byte("changed content"), 5000)
	if err = os.WriteFile(filepath.Join(p, "file"), edited, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = RecompressRecord(t.Context(), s, "file", 2, o); !errors.Is(err, metatransport.ErrConflict) {
		t.Fatal(err)
	}
	o.AllowChangedPayload = true
	next, err := RecompressRecord(t.Context(), s, "file", 2, o)
	if err != nil || !next.Published || next.Generation != 3 || *next.Record.Payload != digest(edited) || reflect.DeepEqual(first.Record.Attributes, next.Record.Attributes) {
		t.Fatal(next, err)
	}
	if !next.Record.Darwin.Modify.Equal(o.Clock().Truncate(time.Microsecond)) {
		t.Fatal("write-open timestamp not retained", next.Record.Darwin)
	}
	checkRecompressionCleanup(t, o.TemporaryDirectory)
}

type recompressionWrappedInput struct {
	hostdata.CompressionInput
	wrap func(hostdata.CompressionStream) hostdata.CompressionStream
}

func (i recompressionWrappedInput) Duplicate() (hostdata.CompressionStream, error) {
	s, err := i.CompressionInput.Duplicate()
	if err != nil {
		return nil, err
	}
	return i.wrap(s), nil
}

type recompressionWrappedStream struct {
	hostdata.CompressionStream
	activate func(hostdata.CompressionStream, uint32, uint32) (uint32, error)
}

func (s recompressionWrappedStream) CompareAndSwapFlags(a, b uint32) (uint32, error) {
	return s.activate(s.CompressionStream, a, b)
}
func recompressionWithActivation(activate func(hostdata.CompressionStream, uint32, uint32) (uint32, error)) recompressionOperation {
	return func(ctx context.Context, open func(context.Context) (hostdata.CompressionInput, error), o hostdata.RecompressionOptions) (hostdata.RecompressionResult, error) {
		return hostdata.Recompress(ctx, func(ctx context.Context) (hostdata.CompressionInput, error) {
			i, e := open(ctx)
			if e != nil {
				return nil, e
			}
			return recompressionWrappedInput{i, func(s hostdata.CompressionStream) hostdata.CompressionStream {
				return recompressionWrappedStream{s, activate}
			}}, nil
		}, o)
	}
}
func TestCarrierRecompressionLateCancellation(t *testing.T) {
	s, _, _, _, o := carrierRecompressionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	op := recompressionWithActivation(func(s hostdata.CompressionStream, a, b uint32) (uint32, error) {
		v, e := s.CompareAndSwapFlags(a, b)
		cancel()
		return v, e
	})
	result, err := recompressRecord(ctx, s, "file", 1, o, op)
	if !errors.Is(err, context.Canceled) || !result.Published || result.Generation != 2 || !result.Operation.Installation.Commit.Activated {
		t.Fatal(result, err)
	}
	attrs, err := s.ReadRecordAttributes(t.Context(), result.Record, 1<<20)
	if err != nil || string(attrs["user.retained"]) != "retained attribute" {
		t.Fatal("late cancellation lost borrowed attribute", attrs, err)
	}
	if err = s.VerifyPayload(t.Context(), result.Record); err != nil {
		t.Fatal(err)
	}
	checkRecompressionCleanup(t, o.TemporaryDirectory)
}
func TestCarrierRecompressionActivationFailure(t *testing.T) {
	s, p, _, _, o := carrierRecompressionFixture(t)
	fail := errors.New("activation failed")
	op := recompressionWithActivation(func(hostdata.CompressionStream, uint32, uint32) (uint32, error) { return 0, fail })
	result, err := recompressRecord(t.Context(), s, "file", 1, o, op)
	if !errors.Is(err, fail) || !result.Published || result.Generation != 2 || result.Operation.Installation.Commit.Activated || !result.Operation.Installation.Commit.DataTruncated {
		t.Fatal(result, err)
	}
	plain, err := os.ReadFile(filepath.Join(p, "file"))
	if err != nil || len(plain) != 0 || *result.Record.Payload != digest(nil) {
		t.Fatal("inactive retained data not empty", plain, err)
	}
	attrs, err := s.ReadRecordAttributes(t.Context(), result.Record, 1<<20)
	if err != nil || len(attrs[hostdata.DecmpfsName]) == 0 || *result.Record.Darwin.Flags&hostdata.UFCompressed != 0 {
		t.Fatal(attrs, err)
	}
	checkRecompressionCleanup(t, o.TemporaryDirectory)
}

func TestCarrierRecompressionGenerationConflict(t *testing.T) {
	s, _, _, _, o := carrierRecompressionFixture(t)
	m, e := s.Load(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	once := false
	o.Clock = func() time.Time {
		if !once {
			once = true
			if e = s.Commit(t.Context(), m, 1); e != nil {
				t.Fatal(e)
			}
		}
		return time.Unix(1700000000, 0)
	}
	result, e := RecompressRecord(t.Context(), s, "file", 1, o)
	if !errors.Is(e, metatransport.ErrConflict) || result.Published {
		t.Fatal(result, e)
	}
	final, e := s.Load(t.Context())
	if e != nil || final.Generation != 2 || !reflect.DeepEqual(final.Records, m.Records) {
		t.Fatal(final, e)
	}
	checkRecompressionCleanup(t, o.TemporaryDirectory)
}
func TestCarrierRecompressionBrokenStorage(t *testing.T) {
	s, _, m, r, o := carrierRecompressionFixture(t)
	if err := os.WriteFile(filepath.Join(m, "blob-"+r.Attributes[0].Value.SHA256), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RecompressRecord(t.Context(), s, "file", 1, o); !errors.Is(err, metatransport.ErrCorrupt) {
		t.Fatal(err)
	}
}
func TestCarrierRecompressionSourceReplacement(t *testing.T) {
	s, p, _, _, o := carrierRecompressionFixture(t)
	once := false
	o.Clock = func() time.Time {
		if !once {
			once = true
			if err := os.Rename(filepath.Join(p, "file"), filepath.Join(p, "old")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "file"), []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return time.Unix(1700000000, 0)
	}
	result, e := RecompressRecord(t.Context(), s, "file", 1, o)
	if !errors.Is(e, metatransport.ErrConflict) || result.Published {
		t.Fatal(result, e)
	}
	data, e := os.ReadFile(filepath.Join(p, "file"))
	if e != nil || !strings.EqualFold(string(data), "replacement") {
		t.Fatal(string(data), e)
	}
}
