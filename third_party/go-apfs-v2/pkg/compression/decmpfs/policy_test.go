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

func TestEncodePolicyCallerOwnership(t *testing.T) {
	plain := bytes.Repeat([]byte("abcd"), 16384)
	f, err := os.Create(filepath.Join(t.TempDir(), "private-stage"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sentinel := []byte("existing caller-owned staging content")
	if _, err := f.Write(sentinel); err != nil {
		t.Fatal(err)
	}
	inline, err := decmpfs.Encode(t.Context(), bytes.NewReader(plain), int64(len(plain)), f, decmpfs.EncodeOptions{})
	if err != nil || inline.ForkSize != 0 || len(inline.Attribute) <= 16 || binary.LittleEndian.Uint32(inline.Attribute[4:8]) != 7 {
		t.Fatalf("inline: %+v %v", inline, err)
	}
	read := make([]byte, len(sentinel))
	if _, err := f.ReadAt(read, 0); err != nil || !bytes.Equal(read, sentinel) {
		t.Fatal("inline changed caller storage", err)
	}
	fork, err := decmpfs.Encode(t.Context(), bytes.NewReader(plain), int64(len(plain)), f, decmpfs.EncodeOptions{Type: 3, ResourceForkOnly: true})
	if err != nil || fork.ForkSize <= 0 || len(fork.Attribute) != 16 || binary.LittleEndian.Uint32(fork.Attribute[4:8]) != 4 {
		t.Fatalf("fork: %+v %v", fork, err)
	}
	if err := f.Truncate(fork.ForkSize); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := decmpfs.Encode(t.Context(), bytes.NewReader(plain), int64(len(plain)), f, decmpfs.EncodeOptions{ResourceForkOnly: true})
	if !errors.Is(err, os.ErrClosed) || got.Attribute != nil || got.ForkSize != 0 {
		t.Fatalf("closed destination: %+v %v", got, err)
	}
}
