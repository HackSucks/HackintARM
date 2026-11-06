package hostdata_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/copypipeline"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestCopyPipelineNative(t *testing.T) {
	data, e := os.ReadFile("../../testdata/appledouble/native/copy-pipeline.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var f copypipeline.Fixture
	if e = json.NewDecoder(z).Decode(&f); e != nil {
		t.Fatal(e)
	}
	helper, e := os.ReadFile("../../testdata/appledouble/native/copy-pipeline.c")
	if e != nil {
		t.Fatal(e)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if f.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(helper)) || f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		t.Fatal("oracle source provenance")
	}
	want := copypipeline.Cases()
	if len(f.Cases) != 2316 || len(f.Cases) != len(want) {
		t.Fatal("incomplete corpus", len(f.Cases))
	}
	for i, c := range f.Cases {
		selection := c
		selection.Native = copypipeline.Observation{}
		if !reflect.DeepEqual(selection, want[i]) {
			t.Fatal("case selection", i)
		}
		t.Run(c.Name, func(t *testing.T) {
			if e := copypipeline.Replay(c); e != nil {
				t.Fatal(e)
			}
		})
	}
}

type pipelineBackend struct {
	run    func(hostdata.CopyStage) hostdata.CopyStageResult
	remove func() error
}

func (b pipelineBackend) Run(s hostdata.CopyStage) hostdata.CopyStageResult { return b.run(s) }
func (b pipelineBackend) RemoveDestination() error                          { return b.remove() }
func TestCopyPipelineValidationAndDiagnostics(t *testing.T) {
	o := hostdata.CopyPipelineOptions{SourceReady: true, DestinationReady: true}
	r, e := hostdata.RunCopyPipeline(o, nil)
	if !errors.Is(e, os.ErrInvalid) || r.Completed || r.Code != -1 || len(r.Steps) != 0 {
		t.Fatal(r, e)
	}
	t.Run("negative-without-error", func(t *testing.T) {
		o.Pack = true
		b := pipelineBackend{run: func(hostdata.CopyStage) hostdata.CopyStageResult { return hostdata.CopyStageResult{Code: -9} }}
		r, e := hostdata.RunCopyPipeline(o, b)
		if e == nil || r.Code != -9 || r.Completed || len(r.Steps) != 1 {
			t.Fatal(r, e)
		}
	})
	t.Run("cleanup-preserves-primary", func(t *testing.T) {
		primary, cleanup := errors.New("primary"), errors.New("cleanup")
		o.Pack = true
		o.HasDestinationPath = true
		b := pipelineBackend{run: func(hostdata.CopyStage) hostdata.CopyStageResult {
			return hostdata.CopyStageResult{Code: -3, Err: primary}
		}, remove: func() error { return cleanup }}
		r, e := hostdata.RunCopyPipeline(o, b)
		if !errors.Is(e, primary) || errors.Is(e, cleanup) || r.Code != -3 || r.Completed || len(r.Steps) != 2 || !errors.Is(r.Steps[1].Result.Err, cleanup) {
			t.Fatal(r, e)
		}
	})
	t.Run("diagnostic-with-zero-code", func(t *testing.T) {
		diagnostic := errors.New("ignored internal operation")
		b := pipelineBackend{run: func(hostdata.CopyStage) hostdata.CopyStageResult { return hostdata.CopyStageResult{Err: diagnostic} }}
		r, e := hostdata.RunCopyPipeline(hostdata.CopyPipelineOptions{SourceReady: true, DestinationReady: true, Stat: true}, b)
		if e != nil || !r.Completed || len(r.Steps) != 2 || !errors.Is(r.Steps[0].Result.Err, diagnostic) || !errors.Is(r.Steps[1].Result.Err, diagnostic) {
			t.Fatal(r, e)
		}
	})
	if got := hostdata.CopyQuarantineError(13).Error(); got != "quarantine application code 13" {
		t.Fatal(got)
	}
}
