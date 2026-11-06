package hostdata

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrMetadataIdentity means an entry changed between no-follow observation and
// descriptor acquisition. No metadata write has been authorized by this call.
var ErrMetadataIdentity = errors.New("metadata entry identity changed while opening")

// OpenMetadataFile opens the named entry itself, including a symlink, within
// root. The result belongs to the caller. A final no-follow stat/descriptor
// comparison rejects replacement; intermediate resolution stays inside root.
// On Windows the handle requests metadata write access without content writes.
// Linux O_PATH symlink handles preserve identity, although individual native
// metadata operations may refuse that handle; retain such values in a carrier.
func OpenMetadataFile(root *os.Root, name string) (*os.File, error) {
	return openMetadataChecked(root, name, openMetadataFile)
}

// OpenMetadataFileRead is the read-only form for source acquisition. In
// particular it does not request Windows WRITE_ATTRIBUTES or WRITE_EA rights.
func OpenMetadataFileRead(root *os.Root, name string) (*os.File, error) {
	return openMetadataChecked(root, name, openMetadataFileRead)
}

func openMetadataChecked(root *os.Root, name string, open func(*os.Root, string, os.FileInfo) (*os.File, error)) (*os.File, error) {
	if root == nil || !filepath.IsLocal(name) {
		return nil, os.ErrInvalid
	}
	before, err := StatMetadata(root, name)
	if err != nil {
		return nil, err
	}
	file, err := open(root, name, before)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if !os.SameFile(before, after) || before.Mode().Type() != after.Mode().Type() {
		return nil, errors.Join(ErrMetadataIdentity, file.Close())
	}
	return file, nil
}

func metadataParent(root *os.Root, name string, open func(*os.File, string) (*os.File, error)) (result *os.File, err error) {
	// Resolve parent components through the held root before interpreting the leaf.
	// Lexical cleaning here changes paths such as link/../file.
	parent, base := filepath.Split(name)
	if base == "" || base == "." || base == ".." {
		parent, base = name, "."
	}
	if parent == "" {
		parent = "."
	}
	directory, err := openMetadataParent(root, parent)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			if result != nil {
				err = errors.Join(err, result.Close())
				result = nil
			}
		}
	}()
	return open(directory, base)
}
