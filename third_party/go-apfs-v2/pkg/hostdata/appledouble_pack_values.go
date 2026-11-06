package hostdata

import (
	"errors"
	"io"
	"math"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func (s *packExecution) value(name string) (value []byte, skip, advance bool, err error) {
	if name == appledouble.ACLTextName || name == appledouble.QuarantineName && s.options.HasQuarantine {
		if name == appledouble.ACLTextName {
			value, err = s.backend.ACL()
		} else {
			value, err = s.backend.Quarantine()
		}
		s.fail("serialize", name, err)
		if name == appledouble.QuarantineName && err != nil {
			// Native leaves the previous length/buffer unspecified here.
			return nil, false, false, errors.Join(ErrPackUnsafe, err)
		}
		if err := s.allocation(uint64(len(value))); err != nil {
			s.fail("allocation", name, err)
			return nil, false, false, err
		}
		return value, false, true, nil
	}
	if s.options.Callback != nil {
		s.result.Copied = 0
		if s.notify(PackProgress, name) == CopyPipelineQuit {
			return nil, false, false, ErrPackCanceled
		}
	}
	size, err := s.backend.XattrSize(name)
	s.fail("size", name, err)
	if err != nil || size < 0 {
		if err == nil {
			return nil, false, false, ErrPackUnsafe
		}
		if s.notify(PackError, name) == CopyPipelineQuit {
			return nil, false, false, ErrPackCanceled
		}
		s.result.Losses = append(s.result.Losses, PackLoss{name, "source size query failed; native leaves empty record"})
		return nil, true, true, nil
	}
	if size == 0 {
		return nil, true, true, nil
	}
	if size > 16<<20 {
		s.result.Losses = append(s.result.Losses, PackLoss{name, "native ordinary-value packing limit exceeds 16 MiB; record left empty"})
		return nil, true, true, nil
	}
	if err := s.allocation(uint64(size)); err != nil {
		s.fail("allocation", name, err)
		s.result.Code = -1
		// Native continues to the next source name without advancing its header
		// cursor after malloc refusal. A later fork result may replace this code.
		return nil, true, false, nil
	}
	value = make([]byte, int(size))
	n, readErr := s.backend.ReadXattr(name, value)
	s.fail("read", name, readErr)
	if s.notify(PackFinish, name) == CopyPipelineQuit {
		return nil, false, false, ErrPackCanceled
	}
	if n < 0 || n > len(value) || readErr != nil {
		// copyfile casts a negative failed-read length to uint32 and then passes
		// it to pwrite. Reject this unsafe path with the actual read diagnostic.
		return nil, false, false, errors.Join(ErrPackUnsafe, readErr)
	}
	return value[:n], false, true, nil
}

func (s *packExecution) finder() error {
	action := s.notify(PackStart, appledouble.FinderInfoName)
	if action == CopyPipelineQuit {
		return ErrPackCanceled
	}
	if action == CopyPipelineSkip {
		return nil
	}
	if s.options.Callback != nil {
		s.result.Copied = 0
		// The native FinderInfo branch clears xattr_name after Start and
		// leaves it clear for its subsequent Progress callback.
		if s.notify(PackProgress, "") == CopyPipelineQuit {
			return ErrPackCanceled
		}
	}
	n, err := s.backend.ReadXattr(appledouble.FinderInfoName, s.header[50:82])
	s.fail("finder-read", appledouble.FinderInfoName, err)
	if err != nil {
		if s.notify(PackError, appledouble.FinderInfoName) == CopyPipelineQuit {
			return err
		}
		s.result.Losses = append(s.result.Losses, PackLoss{appledouble.FinderInfoName, "native FinderInfo read failed"})
		return nil
	}
	if n < 0 || n > 32 {
		return ErrPackUnsafe
	}
	if n == 32 && s.notify(PackFinish, appledouble.FinderInfoName) == CopyPipelineQuit {
		return ErrPackCanceled
	}
	if n != 32 {
		s.result.Losses = append(s.result.Losses, PackLoss{appledouble.FinderInfoName, "native FinderInfo read was shorter than 32 bytes"})
	}
	return nil
}

func (s *packExecution) fork(offset uint64) (code int, err error) {
	name := appledouble.ResourceForkName
	errorName := ""
	// Native calls Error for most failures, including Start/Progress Quit,
	// and Error Continue can clear the return code. A size-query failure is
	// an immediate return and does not invoke Error.
	done := func(failure error) (int, error) {
		s.fail("resource-fork", name, failure)
		if s.options.Callback != nil && s.notify(PackError, errorName) == CopyPipelineContinue {
			return 0, nil
		}
		return -1, failure
	}
	action := s.notify(PackStart, name)
	if action == CopyPipelineSkip {
		return 0, nil
	}
	if action == CopyPipelineQuit {
		return done(ErrPackCanceled)
	}
	size, err := s.backend.XattrSize(name)
	if err != nil {
		s.fail("fork-size", name, err)
		return -1, err
	}
	if size < 0 {
		return -1, ErrPackUnsafe
	}
	if size > math.MaxInt32 {
		return done(appledouble.ErrTooLarge)
	}
	if s.options.Callback != nil {
		s.result.Copied = 0
		if s.notify(PackProgress, name) == CopyPipelineQuit {
			return done(ErrPackCanceled)
		}
	}
	if err := s.allocation(uint64(size)); err != nil {
		return done(err)
	}
	value := make([]byte, int(size))
	n, err := s.backend.ReadXattr(name, value)
	if n < 0 || n > len(value) {
		return done(ErrPackUnsafe)
	}
	if err != nil || n != len(value) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return done(err)
	}
	if err := s.write(name, value, offset); err != nil {
		// Native warns but still records the full fork length and completes.
		s.result.Losses = append(s.result.Losses, PackLoss{name, "native ignores resource-fork output write failure"})
	}
	// The resource-fork helper leaves xattr_name clear after Progress,
	// including at Finish and any subsequent Error callback.
	if s.notify(PackFinish, "") == CopyPipelineQuit {
		return done(ErrPackCanceled)
	}
	s.put32(46, uint32(size))
	return 0, nil
}
