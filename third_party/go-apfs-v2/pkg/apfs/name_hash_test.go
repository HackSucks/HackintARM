package apfs_test

import (
	"os"

	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

// Run in a fresh process: earlier filesystem tests may already have calculated
// name hashes, masking a race in first-use table initialization.
func TestNameHashConcurrentFirstUse(t *testing.T) {
	const child = "APFS_TEST_NAME_HASH_CHILD"
	if os.Getenv(child) != "1" {
		cmd := cirunner.Command(os.Args[0], "-test.run=^TestNameHashConcurrentFirstUse$")
		cmd.Env = append(os.Environ(), child+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("concurrent first use: %v\n%s", err, output)
		}
		return
	}

	// These case-insensitive ASCII hashes also describe native APFS directory
	// order; each UTF encoding must retain the same result under contention.
	vectors := []struct {
		name string
		hash uint32
	}{
		{"CodeResources", 4316},
		{"CodeDirectory", 655443},
		{"CodeRequirements", 2745087},
		{"collision-17818", 87980},
		{"collision-30606", 87980},
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		workers.Go(func() {
			<-start
			for i := 0; i < 64; i++ {
				v := vectors[(worker+i)%len(vectors)]
				var got uint32
				if worker%2 == 0 {
					got = apfs.CalculateNameHash([]byte(v.name), true)
				} else {
					got = apfs.CalculateNameHashFromUTF16(apfs.StringToUTF16(v.name), true)
				}
				if got != v.hash {
					t.Errorf("worker %d: hash(%q) = %d, want %d", worker, v.name, got, v.hash)
				}
			}
		})
	}
	close(start)
	workers.Wait()
}
