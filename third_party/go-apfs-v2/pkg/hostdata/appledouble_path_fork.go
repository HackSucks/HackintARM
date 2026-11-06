package hostdata

import (
	"errors"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// The installed copyfile path route opens named forks above 1 MiB even for
// PACK/UNPACK. Destination open truncates before the route; this is observable
// metadata policy, not only a transfer optimization. Held-object fcopyfile has
// no such path-open stage.
const pathForkThreshold = 1 << 20

type pathForkAccess struct {
	open func(*os.File, bool, uint32) (io.Closer, error)
}
type logicalPathFork struct{}

func (logicalPathFork) Close() error { return nil }

func (p *appleDoublePath) openFork(file *os.File, writable bool) (io.Closer, error) {
	open := p.forkAccess.open
	if open == nil {
		open = openPathResourceForkNative
	}
	fork, err := open(file, writable, p.sourceMetadata.State.Stat.Mode|0200)
	if err != nil && fork != nil {
		return nil, errors.Join(err, fork.Close())
	}
	return fork, err
}
func (p *appleDoublePath) openSourceFork() []HeldLifecycleStep {
	if p.sourceMetadata.State.Stat.Mode&0170000 != 0100000 {
		return nil
	}
	size, err := p.source.attrs.size(appledouble.ResourceForkName)
	if errors.Is(err, os.ErrNotExist) || missingXattr(err) {
		return nil
	}
	steps := []HeldLifecycleStep{{Operation: "source-fork-size", Err: err}}
	if err != nil || size <= pathForkThreshold {
		return steps
	}
	if p.options.Captured != nil {
		p.sourceFork = logicalPathFork{}
		return append(steps, HeldLifecycleStep{Operation: "open-source-fork"})
	}
	p.sourceFork, err = p.openFork(p.sourceFile, false)
	return append(steps, HeldLifecycleStep{Operation: "open-source-fork", Err: err})
}
func (p *appleDoublePath) openDestinationFork() []HeldLifecycleStep {
	if p.sourceFork == nil {
		return nil
	}
	var err error
	if p.options.Captured != nil {
		// Creating/truncating an empty Darwin fork reads back as absent. The
		// logical route must perform this effect on every receiving platform.
		err = p.destination.attrs.truncateFork(p.sourceMetadata.State.Stat.Mode | 0200)
		if err == nil {
			p.destinationFork = logicalPathFork{}
		}
	} else {
		p.destinationFork, err = p.openFork(p.destinationFile, true)
	}
	steps := []HeldLifecycleStep{{Operation: "open-destination-fork", Err: err}}
	if err != nil {
		steps = append(steps, p.closeSourceFork()...)
	}
	return steps
}
func (p *appleDoublePath) closeSourceFork() []HeldLifecycleStep {
	if p.sourceFork == nil {
		return nil
	}
	fork := p.sourceFork
	p.sourceFork = nil
	return []HeldLifecycleStep{{Operation: "close-source-fork", Err: fork.Close()}}
}
func (p *appleDoublePath) closeDestinationFork() []HeldLifecycleStep {
	if p.destinationFork == nil {
		return nil
	}
	fork := p.destinationFork
	p.destinationFork = nil
	return []HeldLifecycleStep{{Operation: "close-destination-fork", Err: fork.Close()}}
}
