//go:build !windows

package procgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

// The grandchild moves to its own process group, so only the parent-pid walk
// can reach it; the child then sleeps so the tree is alive when killed.
func TestHelperTree(t *testing.T) {
	if os.Getenv("PROCGROUP_HELPER") != "tree" {
		return
	}
	cmd := cirunner.Command(os.Args[0], "-test.run=^TestHelperTree$")
	cmd.Env = append(os.Environ(), "PROCGROUP_HELPER=hold")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		os.Exit(8)
	}
	fmt.Println(cmd.Process.Pid)
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestHelperHold(t *testing.T) {
	if os.Getenv("PROCGROUP_HELPER") == "hold" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func alive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func TestAttrCreatesOwnProcessGroup(t *testing.T) {
	cmd := cirunner.Command("sleep", "30")
	cmd.SysProcAttr = Attr()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if pgid != cmd.Process.Pid {
		t.Fatalf("pgid %d is not the child pid %d", pgid, cmd.Process.Pid)
	}
}

func TestKillTreeReachesDetachedGrandchild(t *testing.T) {
	cmd := cirunner.Command(os.Args[0], "-test.run=^TestHelperTree$")
	cmd.Env = append(os.Environ(), "PROCGROUP_HELPER=tree")
	cmd.SysProcAttr = Attr()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(line, err)
	}
	defer func() { _ = syscall.Kill(grandchild, syscall.SIGKILL) }()
	found := false
	for _, pid := range Descendants(cmd.Process.Pid) {
		found = found || pid == grandchild
	}
	if !found {
		t.Fatal("descendant walk missed the detached grandchild")
	}
	if err = KillTree(cmd.Process); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for alive(grandchild) {
		if time.Now().After(deadline) {
			t.Fatal("detached grandchild survived KillTree")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
