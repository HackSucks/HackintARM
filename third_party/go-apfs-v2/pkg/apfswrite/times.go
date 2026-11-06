package apfswrite

import (
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/inodetime"
)

func (b *builder) inodeTimes(e *Entry) ([4]uint64, error) {
	if e.Times == nil {
		t := b.entryTime(e.ModTime)
		return [4]uint64{t, t, t, t}, nil
	}
	return inodetime.Encode(*e.Times, time.Unix(0, int64(b.timestamp)), b.clampTime, false)
}
