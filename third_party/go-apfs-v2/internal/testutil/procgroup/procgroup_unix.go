//go:build !windows

package procgroup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func attr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

func killTree(p *os.Process) error {
	if p == nil {
		return nil
	}
	for _, pid := range descendants(p.Pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	if err := p.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// descendants walks parent pids from a bounded ps listing, so descendants that
// moved to their own process group are still found. ps failing leaves only the
// process group kill.
func descendants(root int) []int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list := cirunner.CommandContext(ctx, "ps", "-axo", "pid=,ppid=")
	list.Options.Heartbeat = time.Hour // The listing is bounded; no progress lines are useful.
	out, err := list.Output()
	if err != nil {
		return nil
	}
	children := map[int][]int{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) != 2 {
			continue
		}
		pid, e1 := strconv.Atoi(string(fields[0]))
		ppid, e2 := strconv.Atoi(string(fields[1]))
		if e1 != nil || e2 != nil || pid == ppid {
			continue
		}
		children[ppid] = append(children[ppid], pid)
	}
	var order []int
	var walk func(int, int)
	walk = func(pid, depth int) {
		if depth > 64 {
			return
		}
		for _, child := range children[pid] {
			walk(child, depth+1)
			order = append(order, child)
		}
	}
	walk(root, 0)
	return order
}
