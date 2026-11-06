package metatransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type nativeValueFault struct {
	size   int64
	err    error
	cancel context.CancelFunc
}

func (v nativeValueFault) Size() int64 { return v.size }
func (v nativeValueFault) ReadAt(p []byte, _ int64) (int, error) {
	if v.cancel != nil {
		v.cancel()
	}
	if v.err != nil {
		return 0, v.err
	}
	clear(p)
	return len(p), nil
}
func TestCarrierStoreNativeValues(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	values := map[string]appledouble.Value{"z": bytes.NewReader(bytes.Repeat([]byte{9}, 200000)), "a": bytes.NewReader(nil)}
	attrs, e := s.StoreAttributeValues(ctx, values)
	if e != nil || len(attrs) != 2 || attrs[0].Name != "a" {
		t.Fatal(attrs, e)
	}
	borrowed, e := s.BorrowAttributes(ctx, attrs)
	if e != nil {
		t.Fatal(e)
	}
	equal, e := equalValues(ctx, values["z"], borrowed["z"])
	if e != nil || !equal {
		t.Fatal(equal, e)
	}
	for _, v := range []map[string]appledouble.Value{{"": bytes.NewReader(nil)}, {"a\x00b": bytes.NewReader(nil)}, {"nil": nil}, {"negative": nativeValueFault{size: -1}}, {"read": nativeValueFault{size: 1, err: io.ErrClosedPipe}}} {
		if _, e = s.StoreAttributeValues(ctx, v); e == nil {
			t.Fatal("accepted bad value")
		}
	}
	for _, a := range [][]Attribute{{{Name: ""}}, {{Name: "a\x00b"}}, {{Name: "a", Value: attrs[0].Value}, {Name: "a", Value: attrs[0].Value}}, {{Name: "a", Value: BlobRef{SHA256: "bad"}}}} {
		if _, e = s.BorrowAttributes(ctx, a); e == nil {
			t.Fatal("accepted bad attr")
		}
	}
	s.limits.Attributes = 0
	if _, e = s.StoreAttributeValues(ctx, values); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	if _, e = s.BorrowAttributes(ctx, attrs); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	s.Close()
	if _, e = s.StoreAttributeValues(ctx, nil); e == nil {
		t.Fatal("closed store")
	}
	if _, e = s.BorrowAttributes(ctx, nil); e == nil {
		t.Fatal("closed store")
	}
}
func TestCarrierReconcileNativeValues(t *testing.T) {
	v := func(s string) appledouble.Value { return bytes.NewReader([]byte(s)) }
	ctx := context.Background()
	logical := map[string]appledouble.Value{"carried": v("original"), "same": v("value")}
	native := map[string]appledouble.Value{"generated": v("baseline"), "same": v("value"), "new": v("new")}
	baseline := map[string]appledouble.Value{"generated": v("baseline"), "same": v("value")}
	out, e := ReconcileValues(ctx, native, baseline, logical)
	if e != nil || len(out) != 3 || out["generated"] != nil {
		t.Fatal(out, e)
	}
	if _, e = ReconcileValues(nil, nil, nil, nil); !errors.Is(e, fs.ErrInvalid) { //nolint:staticcheck // Explicitly test rejection of an invalid nil context.
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = ReconcileValues(cancelled, nil, nil, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, maps := range [][3]map[string]appledouble.Value{
		{{"bad": nil}, nil, nil},
		{nil, {"bad": nativeValueFault{size: -1}}, nil},
		{nil, nil, {"bad": nil}},
		{nil, {"same": v("value")}, logical},
		{{"same": v("changed")}, nil, logical},
		{{"same": v("xxxxx")}, nil, logical},
		{{"same": v("value")}, {"same": nativeValueFault{size: 5, err: io.ErrClosedPipe}}, logical},
		{{"same": nativeValueFault{size: 5, err: io.ErrClosedPipe}}, nil, logical},
		{{"same": v("value")}, nil, {"same": nativeValueFault{size: 5, err: io.ErrClosedPipe}}},
	} {
		if _, e = ReconcileValues(ctx, maps[0], maps[1], maps[2]); e == nil {
			t.Fatal("accepted conflict")
		}
	}
	// A changed host value agreeing with the logical source is harmless.
	if _, e = ReconcileValues(ctx, map[string]appledouble.Value{"same": v("value")}, map[string]appledouble.Value{"same": v("prior")}, logical); e != nil {
		t.Fatal(e)
	}
}
