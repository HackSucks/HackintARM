package decmpfs

import (
	"errors"
	"io"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// UsesResourceFork classifies validated compression headers without reading the
// compressed body. An inline compression attribute does not claim ownership of
// a separate resource fork. Unknown or malformed headers are errors, never a
// reason to silently discard a potentially independent fork.
func UsesResourceFork(value appledouble.Value) (bool, error) {
	if value == nil || value.Size() < HeaderSize {
		return false, fs.ErrInvalid
	}
	prefix := make([]byte, HeaderSize)
	n, err := value.ReadAt(prefix, 0)
	if n != len(prefix) {
		return false, errors.Join(io.ErrUnexpectedEOF, err)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	header, err := ParseHeader(prefix)
	if err != nil || header == nil {
		return false, errors.Join(fs.ErrInvalid, err)
	}
	if _, err = MethodFor(header.CompressionMethod); err != nil {
		return false, err
	}
	return StoresDataInResourceFork(header.CompressionMethod), nil
}
