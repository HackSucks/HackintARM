package procgroup

import (
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestKillTreeAcceptsNilAndExited(t *testing.T) {
	if err := KillTree(nil); err != nil {
		t.Fatal(err)
	}
	cmd := cirunner.Command(os.Args[0], "-test.run=^TestHelperExit$")
	cmd.Env = append(os.Environ(), "PROCGROUP_HELPER=exit")
	cmd.SysProcAttr = Attr()
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := KillTree(cmd.Process); err != nil {
		t.Fatalf("exited process reported %v", err)
	}
}

func TestHelperExit(t *testing.T) {
	if os.Getenv("PROCGROUP_HELPER") == "exit" {
		os.Exit(0)
	}
}
