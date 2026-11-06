package hostdata

import (
	"errors"

	"golang.org/x/sys/unix"
)

const missingXattrError = unix.ENOATTR

func missingXattr(err error) bool { return errors.Is(err, missingXattrError) }
