package recompression

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func digest(data []byte) metatransport.BlobRef {
	sum := sha256.Sum256(data)
	return metatransport.BlobRef{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}
func fixture(t *testing.T) (*metatransport.Store, string, string) {
	t.Helper()
	base := t.TempDir()
	payload, metadata := filepath.Join(base, "payload"), filepath.Join(base, "metadata")
	for _, name := range []string{payload, metadata} {
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := metatransport.Open(payload, metadata, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, payload, metadata
}
func mustBlob(t *testing.T, store *metatransport.Store, data []byte) metatransport.BlobRef {
	t.Helper()
	ref, err := store.PutBlob(t.Context(), bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if ref != digest(data) {
		t.Fatal("stored blob digest differs", ref)
	}
	return ref
}
func fileRecord(t *testing.T, payload string) metatransport.Record {
	t.Helper()
	data := []byte("payload")
	if err := os.WriteFile(filepath.Join(payload, "file"), data, 0600); err != nil {
		t.Fatal(err)
	}
	ref := digest(data)
	return metatransport.Record{Original: "original:name", Materialized: "file", Kind: "file", MaterializedKind: "file", Payload: &ref}
}

// faultCarrier overrides protocol boundaries while retaining the real carrier's
// bounded blobs, associations and publication behavior for every other call.
type faultCarrier struct {
	*metatransport.Store
	openPayload     func(context.Context, string) (*os.File, error)
	load            func(context.Context) (metatransport.Manifest, error)
	borrow          func(context.Context, metatransport.Record) (map[string]appledouble.Value, error)
	storeAttributes func(context.Context, map[string]appledouble.Value) ([]metatransport.Attribute, error)
	publish         func(context.Context, metatransport.Manifest, uint64, func() error) (bool, error)
	checkPayload    func(context.Context, string, interface{ Stat() (os.FileInfo, error) }) error
}

func (s faultCarrier) OpenPayload(ctx context.Context, name string) (*os.File, error) {
	if s.openPayload != nil {
		return s.openPayload(ctx, name)
	}
	return s.Store.OpenPayload(ctx, name)
}
func (s faultCarrier) Load(ctx context.Context) (metatransport.Manifest, error) {
	if s.load != nil {
		return s.load(ctx)
	}
	return s.Store.Load(ctx)
}
func (s faultCarrier) BorrowRecordAttributes(ctx context.Context, r metatransport.Record) (map[string]appledouble.Value, error) {
	if s.borrow != nil {
		return s.borrow(ctx, r)
	}
	return s.Store.BorrowRecordAttributes(ctx, r)
}
func (s faultCarrier) StoreAttributeValues(ctx context.Context, values map[string]appledouble.Value) ([]metatransport.Attribute, error) {
	if s.storeAttributes != nil {
		return s.storeAttributes(ctx, values)
	}
	return s.Store.StoreAttributeValues(ctx, values)
}
func (s faultCarrier) Publish(ctx context.Context, m metatransport.Manifest, generation uint64, transition func() error) (bool, error) {
	if s.publish != nil {
		return s.publish(ctx, m, generation, transition)
	}
	return s.Store.Publish(ctx, m, generation, transition)
}
func (s faultCarrier) CheckPayload(ctx context.Context, name string, file interface{ Stat() (os.FileInfo, error) }) error {
	if s.checkPayload != nil {
		return s.checkPayload(ctx, name, file)
	}
	return s.Store.CheckPayload(ctx, name, file)
}

// Close has the same already-closed contract on every supported host. Stat on
// a closed Windows file instead exposes GetFileType's ERROR_INVALID_HANDLE.
// Do not confuse that backend difference with a leaked descriptor.
func requireFileClosed(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("descriptor was not already closed: %v", err)
	}
}

// Obtain the real closed descriptor's Stat failure for exact propagation checks,
// after independently proving closure through the portable Close contract.
func closedFileStatCause(t *testing.T, file *os.File) error {
	t.Helper()
	requireFileClosed(t, file)
	_, err := file.Stat()
	var pathError *os.PathError
	if !errors.As(err, &pathError) || pathError.Err == nil {
		t.Fatalf("closed descriptor Stat did not report a backend error: %v", err)
	}
	return pathError.Err
}

type failingPayloadStat struct{ err error }

func (f failingPayloadStat) Stat() (os.FileInfo, error) { return nil, f.err }
