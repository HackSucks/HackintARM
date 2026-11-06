package hostdata

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestPathCapturedRemovalValidation(t *testing.T) {
	bad := []CapturedXattrRemoval{{Name: ""}, {Name: "x", Before: []byte{1}}, {Name: "x", After: []byte{1}}, {Name: "x", Errno: 1 << 31}}
	for _, o := range bad {
		a := objectFixture(t).attrs.(*logicalObjectAttributes)
		if err := captureXattrRemovals(a, []CapturedXattrRemoval{o}); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(o, err)
		}
	}
	a := objectFixture(t).attrs.(*logicalObjectAttributes)
	if err := captureXattrRemovals(a, []CapturedXattrRemoval{{Name: "x"}, {Name: "x"}}); !errors.Is(err, ErrXattrListMalformed) {
		t.Fatal(err)
	}
	noSetID := false
	_, err := NewCapturedAppleDoubleObject(CapturedAppleDoubleObject{State: logicalMetadataFixture(t).Snapshot(), Process: QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS26, Absent: true}, Identities: appledouble.ACLIdentitySnapshot{Version: 1}, NoSetID: &noSetID, Removals: bad[:1]})
	if !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
}
func TestPathCapturedRemovalEffects(t *testing.T) {
	t.Run("owned unchanged", func(t *testing.T) {
		a := objectFixture(t, objectAttr("x", "old")).attrs.(*logicalObjectAttributes)
		before, after := []byte("old"), []byte("old")
		if err := captureXattrRemovals(a, []CapturedXattrRemoval{{Name: "x", BeforePresent: true, AfterPresent: true, Before: before, After: after}}); err != nil {
			t.Fatal(err)
		}
		before[0] = '!'
		after[0] = '!'
		for range 2 {
			if err := a.remove("x"); err != nil {
				t.Fatal(err)
			}
		}
		b := make([]byte, 3)
		if n, e := a.read("x", b); e != nil || n != 3 || string(b) != "old" {
			t.Fatal(n, e, b)
		}
	})
	t.Run("mutation and repeated stale", func(t *testing.T) {
		a := objectFixture(t, objectAttr("x", "old")).attrs.(*logicalObjectAttributes)
		if err := captureXattrRemovals(a, []CapturedXattrRemoval{{Name: "x", BeforePresent: true, Before: []byte("old"), Errno: 1}}); err != nil {
			t.Fatal(err)
		}
		if err := a.remove("x"); !errors.Is(err, CapturedDarwinErrno(1)) || err.Error() != "captured Darwin errno 1" {
			t.Fatal(err)
		}
		if len(a.snapshot()) != 0 {
			t.Fatal(a.snapshot())
		}
		if err := a.remove("x"); !errors.Is(err, ErrXattrMutationUncaptured) {
			t.Fatal(err)
		}
	})
	t.Run("absent creates empty", func(t *testing.T) {
		a := objectFixture(t).attrs.(*logicalObjectAttributes)
		if err := captureXattrRemovals(a, []CapturedXattrRemoval{{Name: "x", AfterPresent: true}}); err != nil {
			t.Fatal(err)
		}
		if err := a.remove("x"); err != nil {
			t.Fatal(err)
		}
		if n, e := a.size("x"); n != 0 || e != nil {
			t.Fatal(n, e)
		}
	})
	t.Run("absent remains absent", func(t *testing.T) {
		a := objectFixture(t).attrs.(*logicalObjectAttributes)
		if err := captureXattrRemovals(a, []CapturedXattrRemoval{{Name: "x"}}); err != nil {
			t.Fatal(err)
		}
		if err := a.remove("x"); err != nil {
			t.Fatal(err)
		}
	})
	for _, v := range []appledouble.Value{bytes.NewReader([]byte("long")), bytes.NewReader([]byte("bad")), removalRead{count: 2}, removalRead{err: os.ErrPermission}, removalRead{count: 3, err: io.EOF, data: "old"}} {
		a := objectFixture(t, appledouble.StreamAttr{Name: "x", Value: v}).attrs.(*logicalObjectAttributes)
		if err := captureXattrRemovals(a, []CapturedXattrRemoval{{Name: "x", BeforePresent: true, Before: []byte("old")}}); err != nil {
			t.Fatal(err)
		}
		err := a.remove("x")
		if r, ok := v.(removalRead); ok && r.err == io.EOF {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if !errors.Is(err, ErrXattrMutationUncaptured) {
			t.Fatal(v, err)
		}
		if len(a.snapshot()) != 1 {
			t.Fatal("stale observation mutated destination")
		}
	}
}

type removalRead struct {
	count int
	err   error
	data  string
}

func (removalRead) Size() int64                             { return 3 }
func (v removalRead) ReadAt(p []byte, _ int64) (int, error) { copy(p, v.data); return v.count, v.err }

func TestPathCapturedRemovalDistinctOperations(t *testing.T) {
	info := bytes.Repeat([]byte{1}, 32)
	a := objectFixture(t, appledouble.StreamAttr{Name: appledouble.FinderInfoName, Value: bytes.NewReader(info)}, objectAttr(appledouble.ResourceForkName, "old")).attrs.(*logicalObjectAttributes)
	observations := []CapturedXattrRemoval{{Name: appledouble.FinderInfoName, BeforePresent: true, AfterPresent: true, Before: info, After: info}, {Name: appledouble.ResourceForkName, BeforePresent: true, AfterPresent: true, Before: []byte("old"), After: []byte("old")}}
	if err := captureXattrRemovals(a, observations); err != nil {
		t.Fatal(err)
	}
	if err := a.write(appledouble.FinderInfoName, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.size(appledouble.FinderInfoName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("FinderInfo write used removal observation", err)
	}
	for range 2 {
		if err := a.truncateFork(0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.size(appledouble.ResourceForkName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("named fork truncation used removal observation", err)
	}
}

func TestPathCapturedWriteEffects(t *testing.T) {
	noSetID := false
	seed := CapturedAppleDoubleObject{State: logicalMetadataFixture(t).Snapshot(), Process: QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS26, Absent: true}, Identities: appledouble.ACLIdentitySnapshot{Version: 1}, NoSetID: &noSetID}
	seed.Writes = []CapturedXattrWrite{{Effect: CapturedXattrMutation{Name: ""}}}
	if _, err := NewCapturedAppleDoubleObject(seed); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	seed.Writes = []CapturedXattrWrite{{Effect: CapturedXattrMutation{Name: "x"}}, {Effect: CapturedXattrMutation{Name: "x"}}}
	if _, err := NewCapturedAppleDoubleObject(seed); !errors.Is(err, ErrXattrListMalformed) {
		t.Fatal(err)
	}
	seed.Attributes = []appledouble.StreamAttr{objectAttr("x", "old")}
	before, after, input := []byte("old"), []byte("old"), []byte("new")
	seed.Writes = []CapturedXattrWrite{{Effect: CapturedXattrMutation{Name: "x", BeforePresent: true, AfterPresent: true, Before: before, After: after}, Input: input}}
	object, err := NewCapturedAppleDoubleObject(seed)
	if err != nil {
		t.Fatal(err)
	}
	before[0] = '!'
	after[0] = '!'
	input[0] = '!'
	if err := object.attrs.write("x", []byte("unexpected")); !errors.Is(err, ErrXattrMutationUncaptured) {
		t.Fatal(err)
	}
	for range 2 {
		if err := object.attrs.write("x", []byte("new")); err != nil {
			t.Fatal(err)
		}
	}
	actual := make([]byte, 3)
	if n, e := object.attrs.read("x", actual); n != 3 || e != nil || string(actual) != "old" {
		t.Fatal(n, e, actual)
	}
	if err := object.attrs.remove("x"); err != nil {
		t.Fatal(err)
	}
	if err := object.attrs.write("x", []byte("new")); !errors.Is(err, ErrXattrMutationUncaptured) {
		t.Fatal(err)
	}
}

func TestPathCapturedWritePartialEffects(t *testing.T) {
	for _, errno := range []uint32{0, 1} {
		a := objectFixture(t, objectAttr("x", "old")).attrs.(*logicalObjectAttributes)
		effect := CapturedXattrMutation{Name: "x", BeforePresent: true, Before: []byte("old"), AfterPresent: true, After: []byte("partial"), Errno: errno}
		if err := captureXattrWrites(a, []CapturedXattrWrite{{Effect: effect, Input: []byte("incoming")}}); err != nil {
			t.Fatal(err)
		}
		err := a.write("x", []byte("incoming"))
		if errno == 0 && err != nil || errno != 0 && !errors.Is(err, CapturedDarwinErrno(errno)) {
			t.Fatal(errno, err)
		}
		b := make([]byte, 7)
		if n, e := a.read("x", b); n != 7 || e != nil || string(b) != "partial" {
			t.Fatal(n, e, b)
		}
	}
	a := objectFixture(t, objectAttr("ordinary", "old")).attrs.(*logicalObjectAttributes)
	if err := a.write("ordinary", []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 11)
	if n, e := a.read("ordinary", b); n != 11 || e != nil || string(b) != "replacement" {
		t.Fatal(n, e, b)
	}
	if err := a.remove("ordinary"); err != nil {
		t.Fatal(err)
	}
	if len(a.snapshot()) != 0 {
		t.Fatal(a.snapshot())
	}
}
