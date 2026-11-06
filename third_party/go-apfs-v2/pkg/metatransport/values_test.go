package metatransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestCarrierBorrowedValues(t *testing.T) {
	s, p, m := fixture(t)
	data := bytes.Repeat([]byte("0123456789"), 20000)
	ref := mustBlob(t, s, data)
	v, err := s.BorrowBlob(testContext, ref)
	if err != nil {
		t.Fatal(err)
	}
	if v.Size() != int64(len(data)) {
		t.Fatal(v.Size())
	}
	b := make([]byte, 23)
	n, err := v.ReadAt(b, 99997)
	if err != nil || n != len(b) || !bytes.Equal(b, data[99997:99997+23]) {
		t.Fatalf("read: %d %v", n, err)
	}
	if _, err := v.ReadAt(nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadAt(b, -1); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if n, err := v.ReadAt(b, v.Size()-1); n != 1 || !errors.Is(err, io.EOF) {
		t.Fatalf("end: %d %v", n, err)
	}
	if err := os.WriteFile(filepath.Join(p, "payload"), []byte("changed payload"), 0600); err != nil {
		t.Fatal(err)
	}
	payload, err := s.BorrowPayload(testContext, "payload")
	if err != nil {
		t.Fatal(err)
	}
	if payload.Size() != 15 {
		t.Fatal(payload.Size())
	}
	if _, err := s.BorrowPayload(testContext, "../escape"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := s.BorrowPayload(testContext, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(m, blobName(ref)), filepath.Join(m, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m, blobName(ref)), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadAt(b, 0); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	s.Close()
	if _, err := payload.ReadAt(b, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := s.BorrowPayload(testContext, "payload"); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := s.BorrowBlob(testContext, ref); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestCarrierBorrowRecord(t *testing.T) {
	s, _, _ := fixture(t)
	attrs := map[string][]byte{appledouble.FinderInfoName: make([]byte, 32), appledouble.ResourceForkName: []byte("fork"), "user.example": []byte("value")}
	refs, err := s.StoreAttributes(testContext, attrs)
	if err != nil {
		t.Fatal(err)
	}
	ad, err := appledouble.FromXattrs(attrs).Encode()
	if err != nil {
		t.Fatal(err)
	}
	adRef := mustBlob(t, s, ad)
	r := Record{Attributes: refs, AppleDouble: &adRef}
	values, err := s.BorrowRecordAttributes(testContext, r)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range attrs {
		got, err := io.ReadAll(io.NewSectionReader(values[name], 0, values[name].Size()))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s %v", name, err)
		}
	}
	security := mustBlob(t, s, []byte("security"))
	r.Darwin.Security = &security
	if values, err = s.BorrowRecordAttributes(testContext, r); err != nil || values["com.apple.system.Security"].Size() != 8 {
		t.Fatal(values, err)
	}
	r.Attributes = append(r.Attributes, Attribute{"com.apple.system.Security", security})
	r.AppleDouble = nil
	if _, err = s.BorrowRecordAttributes(testContext, r); err != nil {
		t.Fatal(err)
	}
	other := mustBlob(t, s, []byte("different"))
	r.Darwin.Security = &other
	if _, err = s.BorrowRecordAttributes(testContext, r); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	r.Darwin.Security = nil
	r.Attributes = append(r.Attributes, r.Attributes[0])
	if _, err = s.BorrowRecordAttributes(testContext, r); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	for _, name := range []string{"", "nul\x00name"} {
		if _, err = s.BorrowRecordAttributes(testContext, Record{Attributes: []Attribute{{name, other}}}); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	bad := other
	bad.SHA256 = "invalid"
	if _, err = s.BorrowRecordAttributes(testContext, Record{Attributes: []Attribute{{"value", bad}}}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = s.BorrowRecordAttributes(testContext, Record{Darwin: DarwinState{Security: &bad}}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	s.limits.Attributes = 0
	if _, err = s.BorrowRecordAttributes(testContext, Record{Attributes: refs}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	s.Close()
	if _, err = s.BorrowRecordAttributes(testContext, Record{}); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestCarrierValueReconciliation(t *testing.T) {
	logical := map[string]appledouble.Value{"value": bytes.NewReader([]byte("source"))}
	native := map[string][]byte{"generated": []byte("host"), "new": []byte("edit")}
	baseline := map[string][]byte{"generated": []byte("host")}
	values, err := ReconcileAttributeValues(testContext, native, baseline, logical)
	if err != nil || len(values) != 2 {
		t.Fatal(values, err)
	}
	native["new"][0] = 'x'
	b := make([]byte, 4)
	values["new"].ReadAt(b, 0)
	if string(b) != "edit" {
		t.Fatal("retained mutable caller storage")
	}
	for _, value := range [][]byte{[]byte("other!"), []byte("short")} {
		if _, err := ReconcileAttributeValues(testContext, map[string][]byte{"value": value}, nil, logical); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if _, err := ReconcileAttributeValues(testContext, map[string][]byte{"value": []byte("source")}, nil, logical); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileAttributeValues(testContext, nil, map[string][]byte{"value": []byte("old")}, logical); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err := ReconcileAttributeValues(testContext, nil, nil, map[string]appledouble.Value{"nil": nil}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	//nolint:staticcheck // Missing contexts must be rejected.
	if _, err := ReconcileAttributeValues(nil, nil, nil, nil); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, err := ReconcileAttributeValues(ctx, nil, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type borrowedTestValue struct {
	size int64
	n    int
	err  error
}

func (v borrowedTestValue) Size() int64                           { return v.size }
func (v borrowedTestValue) ReadAt(p []byte, _ int64) (int, error) { return min(v.n, len(p)), v.err }
func TestCarrierBorrowedFailures(t *testing.T) {
	s, p, _ := fixture(t)
	if err := os.WriteFile(filepath.Join(p, "payload"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := s.BorrowPayload(testContext, "payload")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(p, "payload")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	ref := mustBlob(t, s, []byte("not an AppleDouble"))
	if _, err := s.BorrowRecordAttributes(testContext, Record{AppleDouble: &ref}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	fault := errors.New("late read failed")
	for _, tc := range []struct {
		value borrowedTestValue
		want  error
	}{
		{borrowedTestValue{32, 0, io.EOF}, io.ErrUnexpectedEOF},
		{borrowedTestValue{32, 32, fault}, fault},
	} {
		if err := s.validateValueSidecar(testContext, &ref, map[string]appledouble.Value{appledouble.FinderInfoName: tc.value}); !errors.Is(err, tc.want) {
			t.Fatal(err)
		}
	}
	if _, err := ReconcileAttributeValues(testContext, map[string][]byte{"value": []byte("same")}, nil, map[string]appledouble.Value{"value": borrowedTestValue{4, 0, fault}}); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := ReconcileAttributeValues(testContext, nil, nil, map[string]appledouble.Value{"value": borrowedTestValue{-1, 0, nil}}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
