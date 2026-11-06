package hostdata

import (
	"context"
	"os"
)

func filesystemMetadataPath(_ context.Context, file *os.File) (path string, err error) {
	err = withXattrDescriptor(file, func(fd int) error { var e error; path, e = nativeHeldPath(fd); return e })
	return
}
