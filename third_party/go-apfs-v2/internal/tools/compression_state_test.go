package tools

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func TestProjectionInactiveCompression(t *testing.T) {
	for _, header := range [][]byte{projectionCompression(4), []byte("stale"), {}} {
		e := &Extractor{}
		b := &projectionRecorder{}
		flags := uint32(0)
		r := metatransport.Record{Original: "file", Darwin: metatransport.DarwinState{Flags: &flags}}
		attrs := map[string]appledouble.Value{hostdata.DecmpfsName: bytes.NewReader(header), hostdata.ResourceForkName: bytes.NewReader([]byte("retained fork"))}
		if err := e.applyProjection(t.Context(), r, attrs, 1024, b); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(b.events, []string{"xattr:" + hostdata.ResourceForkName, "xattr:" + hostdata.DecmpfsName, "flags"}) {
			t.Fatal(b.events)
		}
		for _, r := range e.NativeProjectionResults() {
			if r.Status != ProjectionApplied {
				t.Fatal(r)
			}
		}
	}
}
