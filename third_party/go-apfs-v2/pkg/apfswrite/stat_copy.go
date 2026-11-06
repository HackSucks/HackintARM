package apfswrite

import (
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/imageacl"
	"github.com/deploymenttheory/go-apfs-v2/internal/unixmode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// CopyStat stages ordered stat restoration into target and its regular hard-link
// aliases. Every destination alias must have explicit Times and matching stat
// metadata. Source modification/access times, numeric ownership, permissions and
// selected flags change; destination birth/change times, xattrs and data remain.
// Nil BSDFlags retains the writer's compression inference. Source compression
// requires destination decmpfs storage when set. A clear flag leaves any
// retained compression metadata inactive; this operation does not copy data.
//
// Applied means all staged writes succeeded and the tree was updated. On any
// validation/execution failure no entry changes; inspect Execution.Failures and
// Execution.VolumeQueries even when execution completed. Serialization must still succeed.
// This pure-Go image operation has no host authorization or kernel timestamp
// side effects. Providers must not mutate the tree; exclude concurrent mutation.
func (root *Entry) CopyStat(target *Entry, source hostdata.StatCopySource, options hostdata.StatCopyOptions) (hostdata.ImageStatCopyResult, error) {
	return imageacl.CopyStat(root, target, source, options, false, (*Entry).imageSecurityNode,
		func(e *Entry) imageacl.StatMetadata { return imageacl.StatMetadata{Times: e.Times, Flags: e.BSDFlags} },
		func(e *Entry, change imageacl.StatChange) {
			e.UID, e.GID = change.UID, change.GID
			e.Mode = e.Mode&^(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) | unixmode.FilePermissions(change.Mode)
			if change.Mode&0170000 == 0040000 {
				e.Mode |= os.ModeDir
			}
			e.ModeExplicit = true
			times, flags := change.Times, change.Flags
			e.Times, e.BSDFlags = &times, &flags
		})
}
