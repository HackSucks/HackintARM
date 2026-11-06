package hostdata

import (
	"context"
	"os"
	"strconv"
)

func filesystemMetadataPath(_ context.Context, file *os.File) (path string, err error) {
	err = withXattrDescriptor(file, func(fd int) error { var e error; path, e = os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); return e })
	return
}
