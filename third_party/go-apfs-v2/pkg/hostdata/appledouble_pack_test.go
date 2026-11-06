package hostdata_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/packnative"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestAppleDoublePackNative(t *testing.T) {
	file, err := os.Open("../../testdata/appledouble/native/pack.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var f packnative.Fixture
	if err := json.NewDecoder(z).Decode(&f); err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile("../../testdata/appledouble/native/pack.c")
	if err != nil {
		t.Fatal(err)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if fmt.Sprintf("%x", sha256.Sum256(helper)) != f.HelperSHA256 || f.SourceSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		t.Fatal("packing source provenance")
	}
	cases := packnative.Cases()
	if len(f.Cases) != 417 || len(cases) != len(f.Cases) {
		t.Fatal("native cases missing")
	}
	for i, c := range f.Cases {
		t.Run(fmt.Sprintf("%03d", i), func(t *testing.T) {
			spec := c
			spec.Native = packnative.Observation{}
			if !reflect.DeepEqual(spec, cases[i]) {
				t.Fatal("native input changed")
			}
			if err := packnative.Replay(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type packBackend struct {
	names                 []string
	data                  map[string][]byte
	size                  func(string) (int64, error)
	read                  func(string, []byte) (int, error)
	write                 func([]byte, int64) (int, error)
	acl, quarantine       []byte
	aclErr, quarantineErr error
	output                []byte
	stat                  hostdata.CopyStageResult
}

func (b *packBackend) ACLPresent() (bool, error)             { return true, nil }
func (b *packBackend) Names(int) ([]string, error)           { return b.names, nil }
func (b *packBackend) PreserveForIntent(string, uint32) bool { return true }
func (b *packBackend) XattrSize(n string) (int64, error) {
	if b.size != nil {
		return b.size(n)
	}
	return int64(len(b.data[n])), nil
}
func (b *packBackend) ReadXattr(n string, d []byte) (int, error) {
	if b.read != nil {
		return b.read(n, d)
	}
	return copy(d, b.data[n]), nil
}
func (b *packBackend) ACL() ([]byte, error)        { return b.acl, b.aclErr }
func (b *packBackend) Quarantine() ([]byte, error) { return b.quarantine, b.quarantineErr }
func (b *packBackend) WriteAt(d []byte, off int64) (int, error) {
	if b.write != nil {
		return b.write(d, off)
	}
	end := int(off) + len(d)
	if end > len(b.output) {
		b.output = append(b.output, make([]byte, end-len(b.output))...)
	}
	copy(b.output[int(off):end], d)
	return len(d), nil
}
func (b *packBackend) Stat() hostdata.CopyStageResult { return b.stat }
func packOptions() hostdata.PackOptions {
	return hostdata.PackOptions{Limits: appledouble.DefaultStreamLimits(), MaxActiveBytes: 32 << 20}
}

func TestAppleDoublePackPreflightAndBudgets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{nil, ctx} {
		if _, err := hostdata.PackAppleDouble(c, packOptions(), &packBackend{}); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
	if _, err := hostdata.PackAppleDouble(context.Background(), packOptions(), nil); err == nil {
		t.Fatal("nil backend")
	}
	for _, name := range []string{"", "a\x00b", strings.Repeat("n", 128)} {
		if _, err := hostdata.PackAppleDouble(context.Background(), packOptions(), &packBackend{names: []string{name}}); !errors.Is(err, hostdata.ErrPackUnsafe) {
			t.Fatal(err)
		}
	}
	many := make([]string, 500)
	for i := range many {
		many[i] = strings.Repeat("n", 127)
	}
	if _, err := hostdata.PackAppleDouble(context.Background(), packOptions(), &packBackend{names: many}); !errors.Is(err, appledouble.ErrTooLarge) {
		t.Fatal(err)
	}
	many = append(many, many...)
	if _, err := hostdata.PackAppleDouble(context.Background(), packOptions(), &packBackend{names: many}); !errors.Is(err, hostdata.ErrPackUnsafe) {
		t.Fatal(err)
	}
	for _, mode := range []string{"header", "value", "total", "active", "output"} {
		t.Run(mode, func(t *testing.T) {
			options := packOptions()
			b := &packBackend{names: []string{"a"}, data: map[string][]byte{"a": {1, 2}}}
			switch mode {
			case "header":
				options.MaxActiveBytes = 0
			case "value":
				options.Limits.MaxValueBytes = 1
			case "total":
				options.Limits.MaxTotalValueBytes = 1
			case "active":
				options.MaxActiveBytes = 2*appledouble.MaxHeader + 1
			case "output":
				options.Limits.MaxFileBytes = 1
			}
			result, err := hostdata.PackAppleDouble(context.Background(), options, b)
			if !errors.Is(err, appledouble.ErrStreamBudget) || result.Code == 0 {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}

func TestAppleDoublePackProviderFailures(t *testing.T) {
	for _, name := range []string{"a", appledouble.FinderInfoName, appledouble.ResourceForkName} {
		for _, n := range []int{-1, 100} {
			b := &packBackend{names: []string{name}, data: map[string][]byte{name: {1}}, read: func(string, []byte) (int, error) { return n, nil }}
			if _, err := hostdata.PackAppleDouble(context.Background(), packOptions(), b); !errors.Is(err, hostdata.ErrPackUnsafe) {
				t.Fatalf("%s count%d: %v", name, n, err)
			}
		}
	}
	for _, name := range []string{"a", appledouble.ResourceForkName} {
		b := &packBackend{names: []string{name}, size: func(string) (int64, error) { return -1, nil }}
		if _, err := hostdata.PackAppleDouble(context.Background(), packOptions(), b); !errors.Is(err, hostdata.ErrPackUnsafe) {
			t.Fatal(err)
		}
	}
	b := &packBackend{names: []string{"a"}, data: map[string][]byte{"a": {1}}, read: func(string, []byte) (int, error) { return 0, os.ErrPermission }}
	if result, err := hostdata.PackAppleDouble(context.Background(), packOptions(), b); !errors.Is(err, os.ErrPermission) || len(result.Failures) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	for _, action := range []hostdata.CopyPipelineAction{hostdata.CopyPipelineContinue, hostdata.CopyPipelineQuit} {
		options := packOptions()
		options.Callback = func(n hostdata.PackNotice) hostdata.CopyPipelineAction {
			if n.Event == hostdata.PackError {
				return action
			}
			return hostdata.CopyPipelineContinue
		}
		b := &packBackend{names: []string{appledouble.FinderInfoName}, read: func(string, []byte) (int, error) { return 0, os.ErrPermission }}
		r, err := hostdata.PackAppleDouble(context.Background(), options, b)
		if len(r.Failures) != 1 || (err != nil) != (action == hostdata.CopyPipelineQuit) {
			t.Fatalf("Finder error %+v %v", r, err)
		}
	}
	for _, n := range []int{-1, 1000} {
		b := &packBackend{write: func([]byte, int64) (int, error) { return n, nil }}
		if _, err := hostdata.PackAppleDouble(context.Background(), packOptions(), b); !errors.Is(err, hostdata.ErrPackUnsafe) {
			t.Fatal(err)
		}
	}
	b = &packBackend{stat: hostdata.CopyStageResult{Code: 7}}
	if result, err := hostdata.PackAppleDouble(context.Background(), packOptions(), b); err == nil || result.Code != 7 {
		t.Fatalf("missing code diagnostic %+v %v", result, err)
	}
}

func TestAppleDoublePackSerializedAndAllocationEffects(t *testing.T) {
	for _, name := range []string{appledouble.ACLTextName, appledouble.QuarantineName} {
		options := packOptions()
		options.HasQuarantine = name == appledouble.QuarantineName
		b := &packBackend{names: []string{name}, aclErr: os.ErrPermission, quarantineErr: os.ErrPermission}
		r, err := hostdata.PackAppleDouble(context.Background(), options, b)
		if len(r.Failures) != 1 || (err != nil) != (name == appledouble.QuarantineName) {
			t.Fatalf("serialize result %+v %v", r, err)
		}
		options.Limits.MaxValueBytes = 1
		b.aclErr, b.quarantineErr = nil, nil
		b.acl, b.quarantine = []byte{1, 2}, []byte{1, 2}
		if _, err := hostdata.PackAppleDouble(context.Background(), options, b); !errors.Is(err, hostdata.ErrPackAllocation) {
			t.Fatal(err)
		}
	}
	// Native ordinary allocation refusal can be masked by the later fork result.
	options := packOptions()
	options.Limits.MaxValueBytes = 1
	b := &packBackend{names: []string{"a", appledouble.ResourceForkName}, data: map[string][]byte{"a": {1, 2}, appledouble.ResourceForkName: {3}}}
	r, err := hostdata.PackAppleDouble(context.Background(), options, b)
	if err != nil || r.Code != 0 || !r.HeaderWritten || len(r.Failures) != 1 {
		t.Fatalf("allocation masking %+v %v", r, err)
	}
	// Fork allocation refusal has the native Error callback's suppression path.
	b = &packBackend{names: []string{appledouble.ResourceForkName}, data: map[string][]byte{appledouble.ResourceForkName: {1, 2}}}
	if _, err := hostdata.PackAppleDouble(context.Background(), options, b); !errors.Is(err, hostdata.ErrPackAllocation) {
		t.Fatal(err)
	}
	options.Callback = func(hostdata.PackNotice) hostdata.CopyPipelineAction { return hostdata.CopyPipelineContinue }
	if r, err := hostdata.PackAppleDouble(context.Background(), options, b); err != nil || len(r.Failures) != 1 {
		t.Fatalf("fork suppress %+v %v", r, err)
	}
}

func TestAppleDoublePackLossAndPartialWrites(t *testing.T) {
	b := &packBackend{names: []string{"a"}, size: func(string) (int64, error) { return 16<<20 + 1, nil }}
	r, err := hostdata.PackAppleDouble(context.Background(), packOptions(), b)
	if err != nil || len(r.Losses) != 1 {
		t.Fatalf("native oversize loss %+v %v", r, err)
	}
	f, err := appledouble.Decode(b.output)
	if err != nil || len(f.Attrs) != 1 || len(f.Attrs[0].Value) != 0 {
		t.Fatalf("missing present-empty record %v", err)
	}
	// A successful lossless codec can still encode this same logical value.
	value := bytes.NewReader(make([]byte, 16<<20+1))
	if _, err := (&appledouble.StreamFile{Attrs: []appledouble.StreamAttr{{Name: "a", Value: value}}}).EncodeTo(context.Background(), io.Discard, appledouble.DefaultStreamLimits()); err != nil {
		t.Fatal(err)
	}
	b = &packBackend{names: []string{appledouble.ResourceForkName}, size: func(string) (int64, error) { return math.MaxInt32 + 1, nil }}
	if _, err := hostdata.PackAppleDouble(context.Background(), packOptions(), b); !errors.Is(err, appledouble.ErrTooLarge) {
		t.Fatal(err)
	}
}

func TestAppleDoublePackCancellationDuringIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	options := packOptions()
	options.Callback = func(n hostdata.PackNotice) hostdata.CopyPipelineAction {
		if n.Event == hostdata.PackProgress {
			cancel()
		}
		return hostdata.CopyPipelineContinue
	}
	b := &packBackend{names: []string{"a"}, data: map[string][]byte{"a": {1}}}
	if _, err := hostdata.PackAppleDouble(ctx, options, b); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	b = &packBackend{names: []string{"a"}, data: map[string][]byte{"a": {1}}, read: func(_ string, d []byte) (int, error) {
		cancel()
		d[0] = 1
		return 1, nil
	}}
	if _, err := hostdata.PackAppleDouble(ctx, packOptions(), b); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
