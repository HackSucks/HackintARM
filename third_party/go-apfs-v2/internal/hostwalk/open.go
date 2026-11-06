package hostwalk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// Tree owns borrowed sources used by Root. Close it after the image writer has
// finished. The caller excludes concurrent edits, including same-size edits.
type Tree[E any] struct {
	Root   E
	Report *fidelity.Report
	owner  *treeOwner
}

// Close invalidates every borrowed value and releases held roots. It is idempotent.
func (t *Tree[E]) Close() error { return t.owner.close() }

type treeOwner struct {
	mu      sync.Mutex
	root    *os.Root
	ctx     context.Context
	closers []io.Closer
	closed  bool
}

// OpenWalk walks without materializing regular-file contents or carrier values.
// Native extended attributes remain subject to the configured capture budget.
func OpenWalk[E any](dir string, opts *Options, mk func(Node, []E) E) (*Tree[E], error) {
	var o Options
	if opts != nil {
		o = *opts
	}
	ctx := o.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	owner := &treeOwner{root: root, ctx: ctx, closers: []io.Closer{root}}
	o.owner = owner
	o.nativeValues = hostdata.CaptureXattrValuesAt
	out, report, err := Walk(dir, &o, mk)
	if err != nil {
		return nil, errors.Join(err, owner.close())
	}
	return &Tree[E]{Root: out, Report: report, owner: owner}, nil
}

func (o *treeOwner) close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	var err error
	for _, closer := range o.closers {
		err = errors.Join(err, closer.Close())
	}
	return err
}

func (o *treeOwner) borrow(name string, info os.FileInfo) (appledouble.Value, error) {
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, fs.ErrInvalid
	}
	return &treeValue{o, filepath.FromSlash(name), info}, nil
}

type treeValue struct {
	owner *treeOwner
	name  string
	info  os.FileInfo
}

func (v *treeValue) Size() int64 { return v.info.Size() }
func (v *treeValue) ReadAt(p []byte, off int64) (n int, err error) {
	o := v.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return 0, fs.ErrClosed
	}
	if err = o.ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	info, err := o.root.Lstat(v.name)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, v.info) || info.Size() != v.Size() {
		return 0, metatransport.ErrConflict
	}
	f, err := o.root.Open(v.name)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err = f.Stat()
	if err != nil {
		return 0, err
	}
	if !os.SameFile(info, v.info) || info.Size() != v.Size() {
		return 0, metatransport.ErrConflict
	}
	return io.NewSectionReader(f, 0, v.Size()).ReadAt(p, off)
}

func nodesEqual(a, b Node) (bool, error) {
	av, bv := nodeValues(a), nodeValues(b)
	ad, bd := a.DataValue, b.DataValue
	if ad == nil {
		ad = bytes.NewReader(a.Data)
	}
	if bd == nil {
		bd = bytes.NewReader(b.Data)
	}
	a.Name, b.Name = "", ""
	a.LinkGroup, b.LinkGroup = 0, 0
	a.Data, b.Data = nil, nil
	a.DataValue, b.DataValue = nil, nil
	a.Xattrs, b.Xattrs = nil, nil
	a.XattrValues, b.XattrValues = nil, nil
	if !reflect.DeepEqual(a, b) || len(av) != len(bv) {
		return false, nil
	}
	equal, err := valuesEqual(ad, bd)
	if err != nil || !equal {
		return equal, err
	}
	for name, v := range av {
		other, ok := bv[name]
		if !ok {
			return false, nil
		}
		equal, err = valuesEqual(v, other)
		if err != nil || !equal {
			return equal, err
		}
	}
	return true, nil
}
func nodeValues(n Node) map[string]appledouble.Value {
	out := make(map[string]appledouble.Value, len(n.Xattrs)+len(n.XattrValues))
	for name, v := range n.Xattrs {
		out[name] = bytes.NewReader(v)
	}
	for name, v := range n.XattrValues {
		out[name] = v
	}
	return out
}
func valuesEqual(a, b appledouble.Value) (bool, error) {
	if a.Size() != b.Size() {
		return false, nil
	}
	pa, pb := make([]byte, 64<<10), make([]byte, 64<<10)
	for off := int64(0); off < a.Size(); {
		count := min(int64(len(pa)), a.Size()-off)
		an, ae := a.ReadAt(pa[:count], off)
		bn, be := b.ReadAt(pb[:count], off)
		if an != int(count) || bn != int(count) {
			return false, errors.Join(io.ErrUnexpectedEOF, ae, be)
		}
		if ae != nil && !errors.Is(ae, io.EOF) {
			return false, ae
		}
		if be != nil && !errors.Is(be, io.EOF) {
			return false, be
		}
		if !bytes.Equal(pa[:count], pb[:count]) {
			return false, nil
		}
		off += count
	}
	return true, nil
}
