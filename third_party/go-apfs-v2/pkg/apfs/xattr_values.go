package apfs

import (
	"fmt"
	"io"
	"io/fs"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// XattrValues returns borrowed, sized readers without materializing attribute
// contents. The volume and its underlying image must remain open and immutable
// until every returned value has been consumed. Callers must not close values.
// Invalid names, duplicate records, unreadable sizes and unsupported size widths
// fail the complete capture; no partial namespace is returned.
func (v *Volume) XattrValues(name string) (map[string]appledouble.Value, error) {
	entry, e := v.entryByFSName("xattrvalues", name)
	if e != nil {
		return nil, e
	}
	values, e := readXattrValues(entry)
	if e != nil {
		return nil, &fs.PathError{Op: "xattrvalues", Path: name, Err: e}
	}
	return values, nil
}

type xattrValueSource interface {
	NumberOfExtendedAttributes() (int, error)
	ExtendedAttributeByIndex(int) (*ExtendedAttribute, error)
}

func readXattrValues(source xattrValueSource) (map[string]appledouble.Value, error) {
	count, e := source.NumberOfExtendedAttributes()
	if e != nil {
		return nil, e
	}
	if count < 0 {
		return nil, fs.ErrInvalid
	}
	out := make(map[string]appledouble.Value, count)
	for i := range count {
		a, e := source.ExtendedAttributeByIndex(i)
		if e != nil {
			return nil, e
		}
		name, e := a.UTF8Name()
		if e != nil {
			return nil, e
		}
		if name == "" || strings.ContainsRune(name, 0) || !utf8.ValidString(name) {
			return nil, fs.ErrInvalid
		}
		if _, present := out[name]; present {
			return nil, fmt.Errorf("duplicate extended attribute %q", name)
		}
		size, e := a.Size()
		if e != nil {
			return nil, e
		}
		if size > math.MaxInt64 {
			return nil, fmt.Errorf("attribute %q size exceeds ReaderAt range", name)
		}
		out[name] = xattrValue{a, int64(size)}
	}
	return out, nil
}

type xattrValue struct {
	reader io.ReaderAt
	size   int64
}

func (v xattrValue) Size() int64 { return v.size }
func (v xattrValue) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(b) == 0 {
		return 0, nil
	}
	if off >= v.size {
		return 0, io.EOF
	}
	want := int64(len(b))
	limit := min(want, v.size-off)
	n, e := v.reader.ReadAt(b[:limit], off)
	if n < 0 || int64(n) > limit {
		return 0, fs.ErrInvalid
	}
	if e == nil && int64(n) < want {
		e = io.EOF
	}
	return n, e
}
