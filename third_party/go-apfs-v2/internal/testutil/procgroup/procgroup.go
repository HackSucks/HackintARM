// Package procgroup isolates a child process in its own process group and
// kills a whole descendant tree on cancellation. The receiver-side native name
// harness uses it so that a probe the kernel will not release cannot keep a CI
// step alive through an inherited descriptor or an unreaped grandchild.
package procgroup

import (
	"os"
	"syscall"
)

// Attr returns the process attributes that place a child in its own process
// group. It is nil on platforms without process groups.
func Attr() *syscall.SysProcAttr { return attr() }

// KillTree force-kills every live descendant of p, p's process group and p
// itself. A process that has already exited is not an error.
func KillTree(p *os.Process) error { return killTree(p) }

// Descendants lists the live processes below pid, deepest first. It is empty
// when the host cannot enumerate processes.
func Descendants(pid int) []int { return descendants(pid) }
