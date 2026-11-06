//go:build windows

package procgroup

import (
	"errors"
	"os"
	"syscall"
)

func attr() *syscall.SysProcAttr { return nil }

func killTree(p *os.Process) error {
	if p == nil {
		return nil
	}
	// A process that Wait already released reports EINVAL here rather than
	// os.ErrProcessDone; both mean there is nothing left to kill.
	if err := p.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func descendants(int) []int { return nil }
