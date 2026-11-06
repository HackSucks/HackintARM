package recompression

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

type publicationFile struct {
	*os.File
	readAt   func([]byte, int64) (int, error)
	write    func([]byte) (int, error)
	seek     func(int64, int) (int64, error)
	truncate func(int64) error
	sync     func() error
}

func (f *publicationFile) ReadAt(p []byte, at int64) (int, error) {
	if f.readAt != nil {
		return f.readAt(p, at)
	}
	return f.File.ReadAt(p, at)
}
func (f *publicationFile) Write(p []byte) (int, error) {
	if f.write != nil {
		return f.write(p)
	}
	return f.File.Write(p)
}
func (f *publicationFile) Seek(at int64, whence int) (int64, error) {
	if f.seek != nil {
		return f.seek(at, whence)
	}
	return f.File.Seek(at, whence)
}
func (f *publicationFile) Truncate(size int64) error {
	if f.truncate != nil {
		return f.truncate(size)
	}
	return f.File.Truncate(size)
}
func (f *publicationFile) Sync() error {
	if f.sync != nil {
		return f.sync()
	}
	return f.File.Sync()
}
func publicationFixture(t *testing.T, copyPayload bool) (*metatransport.Store, *publicationFile, *publicationFile, []recompressionAlias, metatransport.Record, metatransport.BlobRef) {
	t.Helper()
	s, p, m, r := aliasFixture(t)
	before := *r.Payload
	if copyPayload {
		plain := []byte("new logical payload")
		if e := os.WriteFile(filepath.Join(p, r.Materialized), plain, 0600); e != nil {
			t.Fatal(e)
		}
		before = digest(plain)
	}
	data, e := os.OpenFile(filepath.Join(p, r.Materialized), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { data.Close() })
	alias, e := os.OpenFile(filepath.Join(p, "alias"), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { alias.Close() })
	primary, other := &publicationFile{File: data}, &publicationFile{File: alias}
	return s, primary, other, []recompressionAlias{{file: other, record: m.Records[2], baseline: *r.Payload, copyPayload: copyPayload}}, r, before
}
func publicationBytes(t *testing.T, file *os.File) []byte {
	t.Helper()
	info, e := file.Stat()
	if e != nil {
		t.Fatal(e)
	}
	p := make([]byte, info.Size())
	n, e := file.ReadAt(p, 0)
	if n != len(p) || e != nil && !errors.Is(e, io.EOF) {
		t.Fatal(n, e)
	}
	return p
}
func TestCarrierRecompressionPublicationSuccess(t *testing.T) {
	for _, tc := range []struct {
		name                string
		empty, copy         bool
		wantData, wantAlias string
		events              []string
	}{
		{name: "same payload unchanged", wantData: "payload", wantAlias: "payload"},
		{name: "copied payload", copy: true, wantData: "new logical payload", wantAlias: "new logical payload", events: []string{"alias truncate", "alias seek", "alias write", "alias sync"}},
		{name: "empty inode", empty: true, events: []string{"primary truncate", "alias truncate", "primary sync", "alias sync"}},
		{name: "empty edited inode", empty: true, copy: true, events: []string{"primary truncate", "alias truncate", "primary sync", "alias sync"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, data, alias, aliases, r, before := publicationFixture(t, tc.copy)
			var events []string
			data.truncate = func(n int64) error { events = append(events, "primary truncate"); return data.File.Truncate(n) }
			alias.truncate = func(n int64) error { events = append(events, "alias truncate"); return alias.File.Truncate(n) }
			data.sync = func() error { events = append(events, "primary sync"); return data.File.Sync() }
			alias.sync = func() error { events = append(events, "alias sync"); return alias.File.Sync() }
			alias.seek = func(at int64, whence int) (int64, error) {
				events = append(events, "alias seek")
				return alias.File.Seek(at, whence)
			}
			alias.write = func(p []byte) (int, error) { events = append(events, "alias write"); return alias.File.Write(p) }
			if _, e := alias.File.Seek(5, io.SeekStart); e != nil {
				t.Fatal(e)
			}
			if e := publishRecompressionPayload(context.Background(), s, data, aliases, r, before, tc.empty); e != nil {
				t.Fatal(e)
			}
			if got := string(publicationBytes(t, data.File)); got != tc.wantData {
				t.Fatal("primary", got)
			}
			if got := string(publicationBytes(t, alias.File)); got != tc.wantAlias {
				t.Fatal("alias", got)
			}
			if !reflect.DeepEqual(events, tc.events) {
				t.Fatalf("publication order %v, want %v", events, tc.events)
			}
		})
	}
}
func TestCarrierRecompressionPublicationPreflight(t *testing.T) {
	sentinel := errors.New("publication preflight read")
	for _, tc := range []struct {
		name      string
		want      error
		configure func(*publicationFile, *publicationFile, []recompressionAlias, *metatransport.Record, *metatransport.BlobRef)
	}{
		{"primary missing", os.ErrNotExist, func(_, _ *publicationFile, _ []recompressionAlias, r *metatransport.Record, _ *metatransport.BlobRef) {
			r.Materialized = "missing"
		}},
		{"primary replaced", metatransport.ErrConflict, func(_, _ *publicationFile, _ []recompressionAlias, r *metatransport.Record, _ *metatransport.BlobRef) {
			r.Materialized = "alias"
		}},
		{"primary digest", metatransport.ErrCorrupt, func(_, _ *publicationFile, _ []recompressionAlias, _ *metatransport.Record, ref *metatransport.BlobRef) {
			ref.SHA256 = digest(nil).SHA256
		}},
		{"primary size", metatransport.ErrCorrupt, func(_, _ *publicationFile, _ []recompressionAlias, _ *metatransport.Record, ref *metatransport.BlobRef) {
			ref.Size++
		}},
		{"primary read", sentinel, func(data, _ *publicationFile, _ []recompressionAlias, _ *metatransport.Record, _ *metatransport.BlobRef) {
			data.readAt = func([]byte, int64) (int, error) { return 0, sentinel }
		}},
		{"alias missing", os.ErrNotExist, func(_, _ *publicationFile, a []recompressionAlias, _ *metatransport.Record, _ *metatransport.BlobRef) {
			a[0].record.Materialized = "missing"
		}},
		{"alias replaced", metatransport.ErrConflict, func(_, _ *publicationFile, a []recompressionAlias, r *metatransport.Record, _ *metatransport.BlobRef) {
			a[0].record.Materialized = r.Materialized
		}},
		{"alias digest", metatransport.ErrCorrupt, func(_, _ *publicationFile, a []recompressionAlias, _ *metatransport.Record, _ *metatransport.BlobRef) {
			a[0].baseline.SHA256 = digest(nil).SHA256
		}},
		{"alias read", sentinel, func(_, alias *publicationFile, _ []recompressionAlias, _ *metatransport.Record, _ *metatransport.BlobRef) {
			alias.readAt = func([]byte, int64) (int, error) { return 0, sentinel }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, data, alias, aliases, r, before := publicationFixture(t, true)
			tc.configure(data, alias, aliases, &r, &before)
			if e := publishRecompressionPayload(context.Background(), s, data, aliases, r, before, true); !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
			if string(publicationBytes(t, data.File)) != "new logical payload" || string(publicationBytes(t, alias.File)) != "payload" {
				t.Fatal("preflight failure mutated payload")
			}
		})
	}
	t.Run("cancelled preflight", func(t *testing.T) {
		s, data, alias, aliases, r, before := publicationFixture(t, true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if e := publishRecompressionPayload(ctx, s, data, aliases, r, before, true); !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
		if string(publicationBytes(t, data.File)) != "new logical payload" || string(publicationBytes(t, alias.File)) != "payload" {
			t.Fatal("cancelled preflight mutated payload")
		}
	})
	t.Run("all aliases validated before mutation", func(t *testing.T) {
		s, data, alias, aliases, r, before := publicationFixture(t, true)
		second := aliases[0]
		second.baseline.SHA256 = digest(nil).SHA256
		aliases = append(aliases, second)
		if e := publishRecompressionPayload(context.Background(), s, data, aliases, r, before, true); !errors.Is(e, metatransport.ErrCorrupt) {
			t.Fatal(e)
		}
		if string(publicationBytes(t, data.File)) != "new logical payload" || string(publicationBytes(t, alias.File)) != "payload" {
			t.Fatal("later alias validation occurred after mutation")
		}
	})
}
func TestCarrierRecompressionPublicationPartialFailures(t *testing.T) {
	sentinel := errors.New("publication failure")
	for _, tc := range []struct {
		name                string
		empty               bool
		wantData, wantAlias string
		want                error
		configure           func(*publicationFile, *publicationFile)
	}{
		{"primary truncate", true, "new logical payload", "payload", sentinel, func(data, _ *publicationFile) { data.truncate = func(int64) error { return sentinel } }},
		{"alias empty truncate", true, "", "payload", sentinel, func(_, alias *publicationFile) { alias.truncate = func(int64) error { return sentinel } }},
		{"primary sync", true, "", "", sentinel, func(data, _ *publicationFile) { data.sync = func() error { return sentinel } }},
		{"alias empty sync", true, "", "", sentinel, func(_, alias *publicationFile) { alias.sync = func() error { return sentinel } }},
		{"alias copy truncate", false, "new logical payload", "payload", sentinel, func(_, alias *publicationFile) { alias.truncate = func(int64) error { return sentinel } }},
		{"alias seek", false, "new logical payload", "", sentinel, func(_, alias *publicationFile) { alias.seek = func(int64, int) (int64, error) { return 0, sentinel } }},
		{"copy read", false, "new logical payload", "", sentinel, func(data, _ *publicationFile) {
			calls := 0
			data.readAt = func(p []byte, at int64) (int, error) {
				calls++
				if calls > 1 {
					return 0, sentinel
				}
				return data.File.ReadAt(p, at)
			}
		}},
		{"copy short write", false, "new logical payload", "new", io.ErrShortWrite, func(_, alias *publicationFile) {
			alias.write = func(p []byte) (int, error) { return alias.File.Write(p[:3]) }
		}},
		{"copy partial write error", false, "new logical payload", "new", sentinel, func(_, alias *publicationFile) {
			alias.write = func(p []byte) (int, error) {
				n, e := alias.File.Write(p[:3])
				if e != nil {
					return n, e
				}
				return n, sentinel
			}
		}},
		{"alias copy sync", false, "new logical payload", "new logical payload", sentinel, func(_, alias *publicationFile) { alias.sync = func() error { return sentinel } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, data, alias, aliases, r, before := publicationFixture(t, true)
			tc.configure(data, alias)
			if e := publishRecompressionPayload(context.Background(), s, data, aliases, r, before, tc.empty); !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
			if got := string(publicationBytes(t, data.File)); got != tc.wantData {
				t.Fatalf("primary partial state %q, want %q", got, tc.wantData)
			}
			if got := string(publicationBytes(t, alias.File)); got != tc.wantAlias {
				t.Fatalf("alias partial state %q, want %q", got, tc.wantAlias)
			}
		})
	}
}
func TestCarrierRecompressionPublicationCancellationDuringCopy(t *testing.T) {
	for _, atWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "after truncate", true: "after write"}[atWrite], func(t *testing.T) {
			s, data, alias, aliases, r, before := publicationFixture(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			syncCalled := false
			alias.sync = func() error { syncCalled = true; return alias.File.Sync() }
			if atWrite {
				alias.write = func(p []byte) (int, error) { n, e := alias.File.Write(p); cancel(); return n, e }
			} else {
				alias.truncate = func(n int64) error { e := alias.File.Truncate(n); cancel(); return e }
			}
			if e := publishRecompressionPayload(ctx, s, data, aliases, r, before, false); !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			want := []byte(nil)
			if atWrite {
				want = []byte("new logical payload")
			}
			if !bytes.Equal(publicationBytes(t, alias.File), want) || syncCalled {
				t.Fatal("incorrect cancelled publication state")
			}
			if string(publicationBytes(t, data.File)) != "new logical payload" {
				t.Fatal("source changed")
			}
		})
	}
}
