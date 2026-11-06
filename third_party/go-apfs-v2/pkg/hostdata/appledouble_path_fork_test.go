package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestPathResourceForkCapturedLifecycle(t *testing.T) {
	for _, operation := range []PathAppleDoubleOperation{PathPackAppleDouble, PathUnpackAppleDouble} {
		for _, size := range []int{1 << 20, (1 << 20) + 1} {
			source, target := objectFixture(t), objectFixture(t)
			if err := source.attrs.write(appledouble.ResourceForkName, make([]byte, size)); err != nil {
				t.Fatal(err)
			}
			old := []byte("old destination fork suffix")
			if err := target.attrs.write(appledouble.ResourceForkName, old); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
			data := []byte("data")
			if operation == PathUnpackAppleDouble {
				var err error
				data, err = appledouble.FromXattrs(map[string][]byte{appledouble.ResourceForkName: []byte("new")}).Encode()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(src, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, nil, 0600); err != nil {
				t.Fatal(err)
			}
			captured := pathCapturedFixture(t, source, target)
			r, err := CopyAppleDoublePath(context.Background(), src, dst, AppleDoublePathOptions{Operation: operation, Pack: DefaultObjectPackOptions(), Unpack: DefaultObjectUnpackOptions(), MaxOpenAttempts: 8, Captured: captured})
			if err != nil || r.Lifecycle.Code != 0 {
				t.Fatal(r, err)
			}
			value, present := target.attrs.(*logicalObjectAttributes).values[appledouble.ResourceForkName]
			if operation == PathPackAppleDouble && size > pathForkThreshold {
				if present {
					t.Fatal("large-source PACK retained destination logical fork")
				}
				continue
			}
			if !present {
				t.Fatal("expected destination fork")
			}
			want := bytes.Clone(old)
			if operation == PathUnpackAppleDouble {
				// Ordinary destination cleanup removes the listed old fork
				// before the dedicated incoming slot is written.
				want = []byte("new")
			}
			actual, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
			if err != nil || !bytes.Equal(actual, want) {
				t.Fatal(string(actual), string(want), err)
			}
		}
	}
}

type pathForkCloser struct {
	err    error
	closed int
}

func (c *pathForkCloser) Close() error { c.closed++; return c.err }

type pathForkAttrsFailure struct {
	objectAttributes
	sizeErr, removeErr error
}

func (a pathForkAttrsFailure) size(string) (int64, error) { return 0, a.sizeErr }
func (a pathForkAttrsFailure) remove(string) error        { return a.removeErr }
func (a pathForkAttrsFailure) truncateFork(uint32) error  { return a.removeErr }

func TestPathResourceForkLogicalThreshold(t *testing.T) {
	for _, size := range []int{0, 1 << 20, (1 << 20) + 1} {
		for _, present := range []bool{false, true} {
			source, target := objectFixture(t), objectFixture(t)
			source.attrs.(*logicalObjectAttributes).values[appledouble.ResourceForkName] = bytes.NewReader(make([]byte, size))
			if present {
				if e := target.attrs.write(appledouble.ResourceForkName, []byte("old suffix")); e != nil {
					t.Fatal(e)
				}
			}
			p := &appleDoublePath{source: source, destination: target, sourceMetadata: PathMetadata{State: MetadataState{Stat: StatCopySource{Mode: 0100644}}}, options: AppleDoublePathOptions{Captured: &CapturedPathContext{}}}
			sourceSteps := p.openSourceFork()
			destSteps := p.openDestinationFork()
			if (p.sourceFork != nil) != (size > pathForkThreshold) || (p.destinationFork != nil) != (size > pathForkThreshold) {
				t.Fatal(size, sourceSteps, destSteps)
			}
			_, e := target.attrs.size(appledouble.ResourceForkName)
			if (e == nil) != (present && size <= pathForkThreshold) {
				t.Fatal(size, present, e)
			}
			if got := p.Close(); len(got) != map[bool]int{true: 2, false: 0}[size > pathForkThreshold] {
				t.Fatal(got)
			}
			if got := p.Close(); len(got) != 0 {
				t.Fatal("fork closed twice", got)
			}
		}
	}
}
func TestPathResourceForkFallbacks(t *testing.T) {
	marker := errors.New("fork provider refused")
	partial := &pathForkCloser{err: os.ErrPermission}
	pending := &appleDoublePath{forkAccess: pathForkAccess{open: func(*os.File, bool, uint32) (io.Closer, error) { return partial, marker }}}
	if owner, err := pending.openFork(nil, false); owner != nil || !errors.Is(err, marker) || !errors.Is(err, os.ErrPermission) || partial.closed != 1 {
		t.Fatal("partial acquisition not released", owner, err, partial.closed)
	}
	source, target := objectFixture(t), objectFixture(t)
	p := &appleDoublePath{source: source, destination: target}
	if got := p.openSourceFork(); len(got) != 0 {
		t.Fatal(got)
	}
	p.sourceMetadata.State.Stat.Mode = 0100644
	if got := p.openSourceFork(); len(got) != 0 {
		t.Fatal(got)
	}
	original := source.attrs
	source.attrs = pathForkAttrsFailure{objectAttributes: original, sizeErr: marker}
	if got := p.openSourceFork(); len(got) != 1 || !errors.Is(got[0].Err, marker) {
		t.Fatal(got)
	}
	source.attrs = original
	source.attrs.(*logicalObjectAttributes).values[appledouble.ResourceForkName] = bytes.NewReader(make([]byte, (1<<20)+1))
	p.forkAccess.open = func(_ *os.File, write bool, mode uint32) (io.Closer, error) {
		if write || mode != 0100644|0200 {
			t.Fatal(write, mode)
		}
		return nil, marker
	}
	if got := p.openSourceFork(); len(got) != 2 || !errors.Is(got[1].Err, marker) || p.sourceFork != nil {
		t.Fatal(got)
	}
	closer := &pathForkCloser{err: marker}
	p.forkAccess.open = func(_ *os.File, write bool, _ uint32) (io.Closer, error) {
		if write {
			return nil, os.ErrPermission
		}
		return closer, nil
	}
	p.openSourceFork()
	got := p.openDestinationFork()
	if len(got) != 2 || !errors.Is(got[0].Err, os.ErrPermission) || !errors.Is(got[1].Err, marker) || closer.closed != 1 || p.sourceFork != nil {
		t.Fatal(got, closer)
	}
	// A captured publication failure uses the same source-close fallback.
	p.options.Captured = &CapturedPathContext{}
	target.attrs = pathForkAttrsFailure{objectAttributes: target.attrs, removeErr: marker}
	p.openSourceFork()
	got = p.openDestinationFork()
	if len(got) != 2 || !errors.Is(got[0].Err, marker) || p.sourceFork != nil {
		t.Fatal(got)
	}
	// Native successful opens retain both owners until final cleanup.
	p.options.Captured = nil
	first, second := &pathForkCloser{}, &pathForkCloser{err: marker}
	p.forkAccess.open = func(_ *os.File, w bool, _ uint32) (io.Closer, error) {
		if w {
			return second, nil
		}
		return first, nil
	}
	p.openSourceFork()
	p.openDestinationFork()
	p.sourceFile = heldfixture.Source(t, 0600)
	p.destinationFile = heldfixture.Source(t, 0600)
	got = p.Close()
	var names []string
	for _, s := range got {
		names = append(names, s.Operation)
	}
	if !reflect.DeepEqual(names, []string{"close-source", "close-source-fork", "close-destination", "close-destination-fork"}) || !errors.Is(got[3].Err, marker) || first.closed != 1 || second.closed != 1 {
		t.Fatal(got)
	}
}
