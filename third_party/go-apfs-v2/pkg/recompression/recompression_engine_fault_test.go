package recompression

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func TestRecompressionEngineCarrierFailures(t *testing.T) {
	sentinel := errors.New("carrier boundary failure")
	for _, tc := range []struct {
		name      string
		want      error
		configure func(*faultCarrier, *recompressionOperation)
	}{
		{"borrow", sentinel, func(s *faultCarrier, _ *recompressionOperation) {
			s.borrow = func(context.Context, metatransport.Record) (map[string]appledouble.Value, error) {
				return nil, sentinel
			}
		}},
		{"invalid security", appledouble.ErrFileSecurity, func(s *faultCarrier, _ *recompressionOperation) {
			s.borrow = func(context.Context, metatransport.Record) (map[string]appledouble.Value, error) {
				return map[string]appledouble.Value{"com.apple.system.Security": bytes.NewReader([]byte("bad"))}, nil
			}
		}},
		{"open payload", sentinel, func(s *faultCarrier, _ *recompressionOperation) {
			s.openPayload = func(context.Context, string) (*os.File, error) { return nil, sentinel }
		}},
		{"closed payload", os.ErrClosed, func(s *faultCarrier, _ *recompressionOperation) {
			s.openPayload = func(ctx context.Context, name string) (*os.File, error) {
				file, e := s.Store.OpenPayload(ctx, name)
				if e != nil {
					return nil, e
				}
				if e = file.Close(); e != nil {
					t.Fatal(e)
				}
				return file, nil
			}
		}},
		{"invalid borrowed value", metatransport.ErrInvalid, func(s *faultCarrier, _ *recompressionOperation) {
			s.borrow = func(context.Context, metatransport.Record) (map[string]appledouble.Value, error) {
				return map[string]appledouble.Value{"invalid": nil}, nil
			}
		}},
		{"operation before acquisition", sentinel, func(_ *faultCarrier, op *recompressionOperation) {
			*op = func(context.Context, func(context.Context) (hostdata.CompressionInput, error), hostdata.RecompressionOptions) (hostdata.RecompressionResult, error) {
				return hostdata.RecompressionResult{}, sentinel
			}
		}},
		{"closed output", os.ErrClosed, func(_ *faultCarrier, op *recompressionOperation) {
			*op = func(ctx context.Context, open func(context.Context) (hostdata.CompressionInput, error), _ hostdata.RecompressionOptions) (hostdata.RecompressionResult, error) {
				input, e := open(ctx)
				if e != nil {
					return hostdata.RecompressionResult{}, e
				}
				defer input.Close()
				e = input.(*recompressionInput).object.close()
				return hostdata.RecompressionResult{}, e
			}
		}},
		{"reborrow after destructive boundary", sentinel, func(s *faultCarrier, _ *recompressionOperation) {
			calls := 0
			s.borrow = func(ctx context.Context, r metatransport.Record) (map[string]appledouble.Value, error) {
				calls++
				if calls == 2 {
					return nil, sentinel
				}
				return s.Store.BorrowRecordAttributes(ctx, r)
			}
		}},
		{"store output", sentinel, func(s *faultCarrier, _ *recompressionOperation) {
			s.storeAttributes = func(context.Context, map[string]appledouble.Value) ([]metatransport.Attribute, error) {
				return nil, sentinel
			}
		}},
		{"manifest publication", sentinel, func(s *faultCarrier, _ *recompressionOperation) {
			s.publish = func(context.Context, metatransport.Manifest, uint64, func() error) (bool, error) {
				return false, sentinel
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, p, _, r, options := carrierRecompressionFixture(t)
			wrapper := faultCarrier{Store: store}
			op := recompressionOperation(hostdata.Recompress)
			tc.configure(&wrapper, &op)
			result, e := recompressRecord(t.Context(), wrapper, "file", 1, options, op)
			if !errors.Is(e, tc.want) || result.Published {
				t.Fatal(result, e)
			}
			manifest, e := store.Load(t.Context())
			if e != nil || manifest.Generation != 1 || !reflect.DeepEqual(manifest.Records, []metatransport.Record{r}) {
				t.Fatal("failed boundary published state", manifest, e)
			}
			plain, e := os.ReadFile(filepath.Join(p, "file"))
			if e != nil || digest(plain) != *r.Payload {
				t.Fatal("failed boundary changed physical payload", e)
			}
			checkRecompressionCleanup(t, options.TemporaryDirectory)
		})
	}
}
func TestRecompressionEngineVolumeAndSecurity(t *testing.T) {
	t.Run("HFS seconds", func(t *testing.T) {
		s, _, _, r, o := carrierRecompressionFixture(t)
		o.Volume.Filesystem = "hfs"
		// A captured HFS inode already has whole-second timestamps.
		modify, access := r.Darwin.Modify.Truncate(time.Second), r.Darwin.Access.Truncate(time.Second)
		r.Darwin.Modify, r.Darwin.Access = &modify, &access
		if e := s.Commit(t.Context(), metatransport.Manifest{Version: 1, Generation: 1, Records: []metatransport.Record{r}}, 1); e != nil {
			t.Fatal(e)
		}
		got, e := RecompressRecord(t.Context(), s, "file", 2, o)
		if e != nil || !got.Published {
			t.Fatal(got, e)
		}
		if !got.Record.Darwin.Modify.Equal(r.Darwin.Modify.Truncate(time.Second)) || !got.Record.Darwin.Access.Equal(r.Darwin.Access.Truncate(time.Second)) || !got.Record.Darwin.Change.Equal(o.Clock().Truncate(time.Second)) {
			t.Fatal("HFS precision differs", got.Record.Darwin)
		}
	})
	t.Run("default clock", func(t *testing.T) {
		s, _, _, _, o := carrierRecompressionFixture(t)
		o.Clock = nil
		before := time.Now()
		got, e := RecompressRecord(t.Context(), s, "file", 1, o)
		after := time.Now()
		if e != nil || !got.Published || got.Record.Darwin.Change == nil || got.Record.Darwin.Change.Before(before) || got.Record.Darwin.Change.After(after) {
			t.Fatal(got, e)
		}
	})
	t.Run("security bytes retained", func(t *testing.T) {
		s, _, _, r, o := carrierRecompressionFixture(t)
		security := &appledouble.FileSecurity{OwnerUUID: [16]byte{3}, GroupUUID: [16]byte{4}, NoACLFlags: [4]byte{1, 2, 3, 4}, Trailing: []byte("opaque retained security")}
		encoded, e := security.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		r.Attributes = append(r.Attributes, metatransport.Attribute{Name: "com.apple.system.Security", Value: mustBlob(t, s, encoded)})
		if e = s.Commit(t.Context(), metatransport.Manifest{Version: 1, Generation: 1, Records: []metatransport.Record{r}}, 1); e != nil {
			t.Fatal(e)
		}
		got, e := RecompressRecord(t.Context(), s, "file", 2, o)
		if e != nil || !got.Published {
			t.Fatal(got, e)
		}
		attrs, e := s.ReadRecordAttributes(t.Context(), got.Record, 1<<20)
		if e != nil || !bytes.Equal(attrs["com.apple.system.Security"], encoded) {
			t.Fatal("opaque security changed", e)
		}
	})
}
func TestRecompressionEngineAliasPublication(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "coherent inode", true: "conflicting metadata"}[conflict], func(t *testing.T) {
			s, p, _, r, o := carrierRecompressionFixture(t)
			r.LinkGroup = "inode"
			alias := r
			alias.Original, alias.Materialized = "alias", "alias"
			if conflict {
				mode := uint32(0100600)
				alias.Darwin.Mode = &mode
			}
			plain, e := os.ReadFile(filepath.Join(p, "file"))
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(p, "alias"), plain, 0600); e != nil {
				t.Fatal(e)
			}
			if e = s.Commit(t.Context(), metatransport.Manifest{Version: 1, Generation: 1, Records: []metatransport.Record{r, alias}}, 1); e != nil {
				t.Fatal(e)
			}
			var held *os.File
			wrapper := faultCarrier{Store: s, openPayload: func(ctx context.Context, name string) (*os.File, error) {
				f, e := s.OpenPayload(ctx, name)
				if name == "alias" {
					held = f
				}
				return f, e
			}}
			got, e := recompressRecord(t.Context(), wrapper, "file", 2, o, hostdata.Recompress)
			if conflict {
				if !errors.Is(e, metatransport.ErrConflict) || got.Published {
					t.Fatal(got, e)
				}
			} else {
				if e != nil || !got.Published || got.Generation != 3 {
					t.Fatal(got, e)
				}
				if held == nil {
					t.Fatal("alias not acquired")
				}
				requireFileClosed(t, held)
				manifest, e := s.Load(t.Context())
				if e != nil || !reflect.DeepEqual(recompressionAliasState(manifest.Records[0]), recompressionAliasState(manifest.Records[1])) {
					t.Fatal("logical inode aliases diverged", manifest, e)
				}
			}
			checkRecompressionCleanup(t, o.TemporaryDirectory)
		})
	}
}
func TestRecompressionEngineRetainedForks(t *testing.T) {
	for _, forkOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained empty independent fork", true: "generated fork replaces empty original"}[forkOnly], func(t *testing.T) {
			s, _, _, r, o := carrierRecompressionFixture(t)
			r.Attributes = append(r.Attributes, metatransport.Attribute{Name: hostdata.ResourceForkName, Value: mustBlob(t, s, nil)})
			if e := s.Commit(t.Context(), metatransport.Manifest{Version: 1, Generation: 1, Records: []metatransport.Record{r}}, 1); e != nil {
				t.Fatal(e)
			}
			o.Encoding.ResourceForkOnly = forkOnly
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			op := recompressionWithActivation(func(stream hostdata.CompressionStream, a, b uint32) (uint32, error) {
				actual, e := stream.CompareAndSwapFlags(a, b)
				cancel()
				return actual, e
			})
			result, e := recompressRecord(ctx, s, "file", 2, o, op)
			if !errors.Is(e, context.Canceled) || !result.Published || !result.Operation.Installation.Commit.Activated {
				t.Fatal(result, e)
			}
			attrs, e := s.ReadRecordAttributes(t.Context(), result.Record, 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			fork, present := attrs[hostdata.ResourceForkName]
			if !present || forkOnly != (len(fork) > 0) {
				t.Fatalf("retained/generated fork confused present%v extent%d", present, len(fork))
			}
			if string(attrs["user.retained"]) != "retained attribute" {
				t.Fatal("original attribute lost")
			}
			values, e := s.BorrowRecordAttributes(t.Context(), result.Record)
			if e != nil {
				t.Fatal(e)
			}
			if e = validateRecompressionStorage(t.Context(), values, *r.Payload); e != nil {
				t.Fatal("published storage no longer bound to payload", e)
			}
			checkRecompressionCleanup(t, o.TemporaryDirectory)
		})
	}
	t.Run("nonempty independent fork preserved", func(t *testing.T) {
		s, _, _, r, o := carrierRecompressionFixture(t)
		fork := []byte("independent resource data")
		r.Attributes = append(r.Attributes, metatransport.Attribute{Name: hostdata.ResourceForkName, Value: mustBlob(t, s, fork)})
		if e := s.Commit(t.Context(), metatransport.Manifest{Version: 1, Generation: 1, Records: []metatransport.Record{r}}, 1); e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		op := recompressionWithActivation(func(stream hostdata.CompressionStream, a, b uint32) (uint32, error) {
			actual, e := stream.CompareAndSwapFlags(a, b)
			cancel()
			return actual, e
		})
		result, e := recompressRecord(ctx, s, "file", 2, o, op)
		if !errors.Is(e, context.Canceled) || !result.Published || !result.Operation.Installation.Commit.DataTruncated || !result.Operation.Installation.Commit.Activated {
			t.Fatal(result, e)
		}
		attrs, e := s.ReadRecordAttributes(t.Context(), result.Record, 1<<20)
		if e != nil || !bytes.Equal(attrs[hostdata.ResourceForkName], fork) || len(attrs[hostdata.DecmpfsName]) <= 16 {
			t.Fatal("independent resource fork overwritten during inline activation", attrs, e)
		}
		values, e := s.BorrowRecordAttributes(t.Context(), result.Record)
		if e != nil {
			t.Fatal(e)
		}
		if e = validateRecompressionStorage(t.Context(), values, *r.Payload); e != nil {
			t.Fatal(e)
		}
		checkRecompressionCleanup(t, o.TemporaryDirectory)

	})
}

func TestRecompressionEngineClosedPayloadError(t *testing.T) {
	store, _, _, _, options := carrierRecompressionFixture(t)
	var statCause error
	wrapper := faultCarrier{Store: store, openPayload: func(ctx context.Context, name string) (*os.File, error) {
		file, err := store.OpenPayload(ctx, name)
		if err != nil {
			return nil, err
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		statCause = closedFileStatCause(t, file)
		return file, nil
	}}
	result, err := recompressRecord(t.Context(), wrapper, "file", 1, options, hostdata.Recompress)
	if statCause == nil || !errors.Is(err, statCause) || !errors.Is(err, os.ErrClosed) || result.Published {
		t.Fatalf("closed payload must retain both backend Stat and cleanup errors: %+v, %v", result, err)
	}
	checkRecompressionCleanup(t, options.TemporaryDirectory)
}
