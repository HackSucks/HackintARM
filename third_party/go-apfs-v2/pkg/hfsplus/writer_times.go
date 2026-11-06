package hfsplus

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/inodetime"
)

// Resolve once before catalog construction or any output writes. Synthetic
// private nodes keep legacy times; link stubs still use privateDirTime for birth.
func (b *builder) prepareTimes() error {
	for _, n := range b.allNodes {
		t := b.nodeTime(n)
		n.times = [4]hfsTime{t, t, t, t}
		if n.entry.Times != nil {
			v, err := inodetime.Encode(*n.entry.Times, b.defaultTime, b.clampTime, true)
			if err != nil {
				return fmt.Errorf("hfsplus: %s: %w", n.name, err)
			}
			for i := range v {
				n.times[i] = hfsTime(v[i])
			}
		}
	}
	return nil
}
