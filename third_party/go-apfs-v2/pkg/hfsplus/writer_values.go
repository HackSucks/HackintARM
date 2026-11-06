package hfsplus

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func valueSize(v appledouble.Value, blockSize int) (int, error) {
	if v == nil {
		return 0, fmt.Errorf("hfsplus: nil value source")
	}
	n := v.Size()
	if n < 0 || int64(int(n)) != n || uint64(n) > uint64(^uint32(0))*uint64(blockSize) {
		return 0, fmt.Errorf("hfsplus: value size %d exceeds fork bounds", n)
	}
	return int(n), nil
}
func readValue(v appledouble.Value, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	n, err := v.ReadAt(b, 0)
	if n != len(b) {
		return fmt.Errorf("hfsplus: short value read (%d/%d): %w", n, len(b), io.ErrUnexpectedEOF)
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
func validateAttributeName(name string) error {
	if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || len(utf16.Encode([]rune(name))) > 127 {
		return fmt.Errorf("hfsplus: invalid attribute name %q", name)
	}
	if name == decmpfs.ResourceForkName {
		return fmt.Errorf("hfsplus: resource fork belongs in Entry.ResourceFork or ResourceForkValue")
	}
	return nil
}

// validateRootSources rejects content the root directory cannot store, including
// the legacy zero-mode root which is still treated as a directory.
func validateRootSources(root *Entry) error {
	if kind := root.Mode.Type(); kind != 0 && kind != os.ModeDir {
		return fmt.Errorf("hfsplus: volume root must be a directory")
	}
	if root.Data != nil || root.DataValue != nil || root.Open != nil || root.Size != 0 || root.ResourceFork != nil || root.ResourceForkValue != nil {
		return fmt.Errorf("hfsplus: directory root cannot carry data or resource fork sources")
	}
	if _, compressed := compressedValue(root); compressed {
		return fmt.Errorf("hfsplus: directory root cannot carry compressed file content")
	}
	return nil
}

// prepareValueTree owns only bounded inline copies; all large sources remain borrowed.
func prepareValueTree(e *Entry, blockSize int) (*Entry, error) {
	if e == nil {
		return nil, fmt.Errorf("hfsplus: nil child entry")
	}
	out := *e
	out.Xattrs = maps.Clone(e.Xattrs)
	out.XattrValues = maps.Clone(e.XattrValues)
	if out.Xattrs == nil {
		out.Xattrs = map[string][]byte{}
	}
	for name := range e.Xattrs {
		if err := validateAttributeName(name); err != nil {
			return nil, err
		}
	}
	for name, v := range e.XattrValues {
		if err := validateAttributeName(name); err != nil {
			return nil, err
		}
		if _, ok := e.Xattrs[name]; ok {
			return nil, fmt.Errorf("hfsplus: duplicate value source %q", name)
		}
		n, err := valueSize(v, blockSize)
		if err != nil {
			return nil, err
		}
		if name == finderInfoName && n != 32 {
			return nil, fmt.Errorf("hfsplus: FinderInfo requires exactly 32 bytes")
		}
		if n <= maxInlineAttrSize(blockSize) || name == finderInfoName {
			b := make([]byte, n)
			if err = readValue(v, b); err != nil {
				return nil, err
			}
			out.Xattrs[name] = b
			delete(out.XattrValues, name)
		}
	}
	if e.DataValue != nil {
		if e.Data != nil || e.Open != nil || e.Size != 0 || e.Mode.IsDir() || e.Mode&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("hfsplus: conflicting or non-file DataValue")
		}
		n, err := valueSize(e.DataValue, blockSize)
		if err != nil {
			return nil, err
		}
		out.Size = int64(n)
		out.Open = func() (io.ReadCloser, error) {
			if e.DataValue.Size() != int64(n) {
				return nil, fmt.Errorf("hfsplus: data value size changed")
			}
			return io.NopCloser(io.NewSectionReader(e.DataValue, 0, int64(n))), nil
		}
		out.DataValue = nil
	}
	if e.ResourceForkValue != nil {
		if e.ResourceFork != nil || e.Mode.IsDir() || e.Mode&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("hfsplus: conflicting or non-file ResourceForkValue")
		}
		if _, err := valueSize(e.ResourceForkValue, blockSize); err != nil {
			return nil, err
		}
	}
	out.Children = make([]*Entry, len(e.Children))
	for i, child := range e.Children {
		var err error
		out.Children[i], err = prepareValueTree(child, blockSize)
		if err != nil {
			return nil, err
		}
	}
	return &out, nil
}
func resourceSize(e *Entry) int {
	if e.ResourceForkValue != nil {
		return int(e.ResourceForkValue.Size())
	}
	return len(e.ResourceFork)
}
func compressedValue(e *Entry) (appledouble.Value, bool) {
	if v, ok := e.XattrValues[decmpfs.AttributeName]; ok {
		return v, true
	}
	b, ok := e.Xattrs[decmpfs.AttributeName]
	return bytes.NewReader(b), ok
}
func validateCompressedValue(e *Entry) error {
	v, ok := compressedValue(e)
	if !ok || e.BSDFlags != nil && *e.BSDFlags&ufCompressed == 0 {
		return nil
	}
	header := make([]byte, min(v.Size(), int64(decmpfs.HeaderSize)))
	if err := readValue(v, header); err != nil {
		return err
	}
	return decmpfs.ValidateLayout(header, uint64(v.Size()), uint64(e.dataLen()), uint64(resourceSize(e)))
}
func writeValue(w io.WriterAt, off int64, v appledouble.Value, size int) error {
	if v.Size() != int64(size) {
		return fmt.Errorf("hfsplus: value size changed")
	}
	buf := make([]byte, min(size, contentBufferSize))
	for pos := 0; pos < size; {
		b := buf[:min(len(buf), size-pos)]
		n, err := v.ReadAt(b, int64(pos))
		if n != len(b) {
			return fmt.Errorf("hfsplus: value short read: %w", io.ErrUnexpectedEOF)
		}
		if err != nil && err != io.EOF {
			return err
		}
		n, err = w.WriteAt(b, off+int64(pos))
		if err != nil {
			return err
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		pos += n
	}
	return nil
}

func validateLayoutBlocks(data uint64, catalog, attrs uint32, blockSize int, requested int64) error {
	// Calculate the bitmap fixed point using wide arithmetic, reserving the
	// alternate header and free block required by computeLayout.
	total := data + uint64(catalog) + uint64(attrs) + 4
	for range 8 {
		bitmap := ((total+7)/8 + uint64(blockSize) - 1) / uint64(blockSize)
		next := data + uint64(catalog) + uint64(attrs) + 4 + bitmap
		if next <= total {
			break
		}
		total = next
	}
	if total > uint64(^uint32(0)) || requested < 0 || uint64(requested/int64(blockSize)) > uint64(^uint32(0)) {
		return fmt.Errorf("hfsplus: image exceeds 32-bit allocation block address space")
	}
	return nil
}
