package decmpfs_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

func TestEncodeForkCallerOwnership(t *testing.T) {
	plain := bytes.Repeat([]byte("public bounded compression transport"), 4000)
	target, err := os.Create(filepath.Join(t.TempDir(), "fork"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	result, err := decmpfs.EncodeFork(t.Context(), bytes.NewReader(plain), int64(len(plain)), 3, target)
	if err != nil {
		t.Fatal(err)
	}
	if result.Size <= 0 || binary.LittleEndian.Uint32(result.Attribute[4:8]) != 4 || binary.LittleEndian.Uint64(result.Attribute[8:]) != uint64(len(plain)) {
		t.Fatalf("invalid result: %+v", result)
	}
	// Caller retains ownership, including truncation of reused destination files.
	if err := target.Truncate(result.Size); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := decmpfs.EncodeFork(t.Context(), bytes.NewReader(plain), int64(len(plain)), 4, target)
	if !errors.Is(err, os.ErrClosed) || got != (decmpfs.EncodedFork{}) {
		t.Fatalf("closed destination: %+v %v", got, err)
	}
}
