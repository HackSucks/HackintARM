package nativeevidence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func fixture(t *testing.T) (Contract, Bundle, Receipt, fstest.MapFS) {
	t.Helper()
	c := Contract{Schema: Schema, ID: "replacement", Profiles: []string{"macos15"}, Consumers: []string{"linux"}, Cases: []string{"APFS/ordinary", "HFS+/denied"}, Comparator: "replacement/v1"}
	hash, err := ContractDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	store := fstest.MapFS{}
	put := func(value string) string {
		h := Digest([]byte(value))
		store["blobs/"+h] = &fstest.MapFile{Data: []byte(value)}
		return h
	}
	execution := Execution{Repository: "apfs", Revision: "current", Run: "123", Attempt: "1", Job: "producer15", Go: "current-go", Sources: map[string]string{"go.mod": put("current module")}}
	b := Bundle{Schema: Schema, Complete: true, Execution: execution, Observation: Observation{Schema: Schema, Contract: hash, Profile: "macos15"}, Capture: Capture{Profile: "macos15", Environment: map[string]string{"os_version": "15.7", "os_build": "24G", "architecture": "arm64", "compiler": "clang", "sdk": "original-sdk"}, Sources: map[string]string{"probe.c": put("original C bytes")}, Artifacts: map[string]string{"native-output": put("original transcript")}}}
	for _, id := range c.Cases {
		b.Observation.Cases = append(b.Observation.Cases, Case{id, put(id + "/input"), put(id + "/native")})
	}
	r := Receipt{Schema: Schema, Contract: hash, Observation: ObservationDigest(b.Observation), Consumer: "linux", Execution: execution, Complete: true, Cases: map[string]string{}, Artifacts: map[string]string{"tests.jsonl": Digest([]byte("current Go transcript"))}}
	for _, id := range c.Cases {
		r.Cases[id] = "pass"
	}
	return c, b, r, store
}

func clone[T any](value T) T {
	b, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}

func TestOriginalProvenanceAndCurrentExecutionAreIndependent(t *testing.T) {
	c, b, r, store := fixture(t)
	if err := VerifyBundle(context.Background(), store, c, b, &b.Execution); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(c, b, r, r.Execution); err != nil {
		t.Fatal(err)
	}
	if err := Aggregate([]Contract{c}, []Bundle{b}, []Receipt{r}, r.Execution); err != nil {
		t.Fatal(err)
	}
	old := clone(b)
	old.Execution.Revision = "old checkout"
	old.Execution.Go = "old go"
	delete(store, "blobs/"+old.Execution.Sources["go.mod"])
	if err := VerifyBundle(context.Background(), store, c, old, nil); err != nil {
		t.Fatal("historical provenance invalidated", err)
	}
	if ObservationDigest(old.Observation) != ObservationDigest(b.Observation) {
		t.Fatal("execution changed oracle")
	}
	if err := VerifyBundle(context.Background(), store, c, old, &b.Execution); err == nil {
		t.Fatal("old execution accepted in fresh qualification")
	}
	diff, err := Compare(old.Observation, b.Observation)
	if err != nil || len(diff) != 0 {
		t.Fatal("provenance became behavior", diff, err)
	}
	// Changing this consumer's dependency/toolchain is recorded separately.
	r.Execution.Go = "new go"
	if err := VerifyReceipt(c, old, r, r.Execution); err != nil {
		t.Fatal(err)
	}
}

func TestContractInventoryAndCycles(t *testing.T) {
	c, _, _, _ := fixture(t)
	mutations := []func(*Contract){func(c *Contract) { c.Schema++ }, func(c *Contract) { c.ID = "" }, func(c *Contract) { c.Comparator = "" }, func(c *Contract) { c.Cases = nil }, func(c *Contract) { c.Profiles = nil }, func(c *Contract) { c.Cases = append(c.Cases, c.Cases[0]) }, func(c *Contract) { c.Profiles = append(c.Profiles, "") }, func(c *Contract) { c.Prerequisites = []string{" space "} }}
	for i, mutate := range mutations {
		bad := clone(c)
		mutate(&bad)
		if _, err := ContractDigest(bad); err == nil {
			t.Fatalf("invalid contract %d accepted", i)
		}
	}
	for _, catalog := range [][]Contract{nil, {c, c}, {func() Contract { x := clone(c); x.Prerequisites = []string{"absent"}; return x }()}, {func() Contract { x := clone(c); x.Prerequisites = []string{c.ID}; return x }()}} {
		if err := ValidateCatalog(catalog); err == nil {
			t.Fatal("invalid catalog accepted")
		}
	}
	parent := clone(c)
	parent.ID = "parent"
	c.Prerequisites = []string{"parent"}
	if err := ValidateCatalog([]Contract{c, parent}); err != nil {
		t.Fatal(err)
	}
	parent.Prerequisites = []string{c.ID}
	if err := ValidateCatalog([]Contract{c, parent}); err == nil {
		t.Fatal("cycle accepted")
	}
	parent.Prerequisites = nil
	if err := ValidateCatalog([]Contract{parent, c}); err != nil {
		t.Fatal(err)
	}
	ordered := clone(c)
	ordered.Cases = []string{c.Cases[1], c.Cases[0]}
	a, _ := ContractDigest(c)
	d, _ := ContractDigest(ordered)
	if a != d || c.Cases[0] != "APFS/ordinary" {
		t.Fatal("contract ordering mutates inputs")
	}
}

func TestNativeBundleFailures(t *testing.T) {
	c, original, _, store := fixture(t)
	mutations := []func(*Bundle){
		func(b *Bundle) { b.Schema++ }, func(b *Bundle) { b.Complete = false }, func(b *Bundle) { b.Observation.Schema++ }, func(b *Bundle) { b.Observation.Contract = "wrong" },
		func(b *Bundle) { b.Capture.Profile = "macos27" }, func(b *Bundle) { b.Observation.Profile = "unknown"; b.Capture.Profile = "unknown" },
		func(b *Bundle) { delete(b.Capture.Environment, "sdk") }, func(b *Bundle) { b.Capture.Sources = nil }, func(b *Bundle) { b.Capture.Artifacts = nil },
		func(b *Bundle) { b.Execution.Repository = "other" }, func(b *Bundle) { b.Execution.Revision = "other" }, func(b *Bundle) { b.Execution.Run = "other" }, func(b *Bundle) { b.Execution.Attempt = "other" },
		func(b *Bundle) { b.Execution.Job = "" }, func(b *Bundle) { b.Execution.Go = "" }, func(b *Bundle) { b.Execution.Sources = nil },
		func(b *Bundle) { b.Execution.Sources["../outside"] = Digest(nil) }, func(b *Bundle) { b.Execution.Sources["go.mod"] = "invalid" },
		func(b *Bundle) { b.Observation.Prerequisites = map[string]string{"unexpected": Digest(nil)} },
		func(b *Bundle) { b.Observation.Cases = b.Observation.Cases[:1] }, func(b *Bundle) { b.Observation.Cases[1] = b.Observation.Cases[0] }, func(b *Bundle) { b.Observation.Cases[1].ID = "unexpected" },
		func(b *Bundle) { b.Observation.Cases[0].Input = "invalid" }, func(b *Bundle) { b.Observation.Cases[0].Result = Digest([]byte("missing")) }, func(b *Bundle) { b.Capture.Sources[""] = Digest(nil) },
	}
	for i, mutate := range mutations {
		b := clone(original)
		mutate(&b)
		if err := VerifyBundle(context.Background(), store, c, b, &original.Execution); err == nil {
			t.Fatalf("invalid bundle %d accepted", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifyBundle(ctx, store, c, original, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	bad := clone(store)
	bad["blobs/"+original.Observation.Cases[0].Input].Data = []byte("corrupted")
	if err := VerifyBundle(context.Background(), bad, c, original, nil); err == nil {
		t.Fatal("corrupted input accepted")
	}
	badContract := clone(c)
	badContract.Schema++
	if err := VerifyBundle(context.Background(), store, badContract, original, nil); err == nil {
		t.Fatal("bad contract accepted")
	}
	parent := clone(c)
	parent.ID = "parent"
	c.Prerequisites = []string{parent.ID}
	hash, _ := ContractDigest(c)
	original.Observation.Contract = hash
	original.Observation.Prerequisites = map[string]string{parent.ID: "invalid"}
	if err := VerifyBundle(context.Background(), store, c, original, nil); err == nil {
		t.Fatal("invalid prerequisite accepted")
	}
	original.Observation.Prerequisites[parent.ID] = Digest([]byte("parent"))
	if err := VerifyBundle(context.Background(), store, c, original, nil); err != nil {
		t.Fatal(err)
	}
}

type brokenStore struct {
	fs.FS
	readErr, closeErr bool
}
type brokenFile struct {
	fs.File
	readErr, closeErr bool
}

func (s brokenStore) Open(name string) (fs.File, error) {
	f, e := s.FS.Open(name)
	if e != nil {
		return nil, e
	}
	return brokenFile{f, s.readErr, s.closeErr}, nil
}
func (f brokenFile) Read(b []byte) (int, error) {
	if f.readErr {
		return 0, io.ErrUnexpectedEOF
	}
	return f.File.Read(b)
}
func (f brokenFile) Close() error {
	err := f.File.Close()
	if f.closeErr {
		return fs.ErrPermission
	}
	return err
}
func TestOriginalArchiveIOFailures(t *testing.T) {
	c, b, _, store := fixture(t)
	for _, s := range []brokenStore{{store, true, false}, {store, false, true}} {
		if err := VerifyBundle(context.Background(), s, c, b, nil); err == nil {
			t.Fatal("archive IO failure accepted")
		}
	}
}

func TestCancellationDuringArchiveRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (contextReader{ctx, strings.NewReader("original")}).Read(make([]byte, 16))
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read proceeded", err)
	}
}

func TestAllDeclaredConsumersAreRequired(t *testing.T) {
	c, b, r, _ := fixture(t)
	c.Consumers = []string{"linux", "windows2022", "windows2025", "macos15", "macos26", "macos27"}
	hash, err := ContractDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	b.Observation.Contract = hash
	r.Contract = hash
	r.Observation = ObservationDigest(b.Observation)
	var receipts []Receipt
	for _, consumer := range c.Consumers {
		next := clone(r)
		next.Consumer = consumer
		receipts = append(receipts, next)
	}
	if err := Aggregate([]Contract{c}, []Bundle{b}, receipts, r.Execution); err != nil {
		t.Fatal(err)
	}
	for i := range receipts {
		missing := append([]Receipt{}, receipts[:i]...)
		missing = append(missing, receipts[i+1:]...)
		if err := Aggregate([]Contract{c}, []Bundle{b}, missing, r.Execution); err == nil {
			t.Fatal("missing consumer accepted", receipts[i].Consumer)
		}
	}
	bad := clone(r)
	bad.Consumer = "unknown"
	if err := VerifyReceipt(c, b, bad, r.Execution); err == nil {
		t.Fatal("unexpected consumer accepted")
	}
	for _, mutate := range []func(*Bundle){func(b *Bundle) { b.Capture.Environment["os_version"] = "27.0" }, func(b *Bundle) { b.Execution.Go = "stale" }, func(b *Bundle) { b.Execution.Sources["go.mod"] = Digest([]byte("other")) }} {
		bad := clone(b)
		mutate(&bad)
		if err := VerifyBundle(context.Background(), fstest.MapFS{}, c, bad, &b.Execution); err == nil {
			t.Fatal("mixed provenance accepted")
		}
	}
}

func TestReceiptFailures(t *testing.T) {
	c, b, r, _ := fixture(t)
	for _, mutate := range []func(*Receipt){
		func(r *Receipt) { r.Artifacts = nil },
		func(r *Receipt) { r.Artifacts = map[string]string{"../outside": Digest(nil)} },
		func(r *Receipt) { r.Artifacts = map[string]string{"tests.jsonl": "invalid"} },
	} {
		bad := clone(r)
		mutate(&bad)
		if err := VerifyReceipt(c, b, bad, r.Execution); err == nil {
			t.Fatal("invalid verification artifact accepted")
		}
	}
	for i, mutate := range []func(*Receipt){func(r *Receipt) { r.Schema++ }, func(r *Receipt) { r.Complete = false }, func(r *Receipt) { r.Contract = "wrong" }, func(r *Receipt) { r.Observation = "wrong" }, func(r *Receipt) { r.Execution.Run = "wrong" }, func(r *Receipt) { delete(r.Cases, c.Cases[0]) }, func(r *Receipt) { r.Cases[c.Cases[0]] = "skip" }, func(r *Receipt) { r.Cases[c.Cases[0]] = "fail" }} {
		bad := clone(r)
		mutate(&bad)
		if err := VerifyReceipt(c, b, bad, r.Execution); err == nil {
			t.Fatalf("invalid receipt %d accepted", i)
		}
	}
	c.Schema++
	if err := VerifyReceipt(c, b, r, r.Execution); err == nil {
		t.Fatal("invalid contract accepted")
	}
}

func TestNativeDifferenceDoesNotBlessGoResults(t *testing.T) {
	_, b, _, _ := fixture(t)
	a := b.Observation
	current := clone(a)
	current.Cases[0].Input = Digest([]byte("new input"))
	current.Cases[0].Result = Digest([]byte("different native output"))
	current.Cases = current.Cases[:1]
	current.Cases = append(current.Cases, Case{"added", Digest(nil), Digest(nil)})
	diff, err := Compare(a, current)
	if err != nil {
		t.Fatal(err)
	}
	want := []Difference{{"APFS/ordinary", "input"}, {"APFS/ordinary", "result"}, {"HFS+/denied", "removed"}, {"added", "added"}}
	if !reflect.DeepEqual(diff, want) {
		t.Fatal(diff)
	}
	for i, mutate := range []func(*Observation){func(o *Observation) { o.Schema++ }, func(o *Observation) { o.Profile = "other" }, func(o *Observation) { o.Contract = "other" }, func(o *Observation) { o.Prerequisites = map[string]string{"parent": Digest(nil)} }, func(o *Observation) { o.Cases[1] = o.Cases[0] }, func(o *Observation) { o.Cases[0].ID = "" }, func(o *Observation) { o.Cases[0].Result = strings.Repeat("A", 64) }} {
		bad := clone(a)
		mutate(&bad)
		if _, err := Compare(a, bad); err == nil {
			t.Fatalf("invalid comparison %d accepted", i)
		}
	}
}

func TestAggregationRejectsMissingOrMixedQualification(t *testing.T) {
	c, b, r, _ := fixture(t)
	tests := []struct {
		bundles  []Bundle
		receipts []Receipt
	}{{nil, nil}, {[]Bundle{b}, nil}, {[]Bundle{b, b}, []Receipt{r}}, {[]Bundle{b}, []Receipt{r, r}}}
	for _, test := range tests {
		if err := Aggregate([]Contract{c}, test.bundles, test.receipts, r.Execution); err == nil {
			t.Fatal("incomplete aggregation accepted")
		}
	}
	bad := clone(b)
	bad.Observation.Contract = "other"
	if err := Aggregate([]Contract{c}, []Bundle{bad}, nil, r.Execution); err == nil {
		t.Fatal("unknown contract accepted")
	}
	bad = clone(b)
	bad.Complete = false
	if err := Aggregate([]Contract{c}, []Bundle{bad}, nil, r.Execution); err == nil {
		t.Fatal("incomplete producer accepted")
	}
	bad = clone(b)
	bad.Execution.Run = "other"
	if err := Aggregate([]Contract{c}, []Bundle{bad}, nil, r.Execution); err == nil {
		t.Fatal("mixed producer accepted")
	}
	badReceipt := clone(r)
	badReceipt.Observation = "unknown"
	if err := Aggregate([]Contract{c}, []Bundle{b}, []Receipt{badReceipt}, r.Execution); err == nil {
		t.Fatal("unknown receipt accepted")
	}
	badReceipt = clone(r)
	badReceipt.Cases[c.Cases[0]] = "fail"
	if err := Aggregate([]Contract{c}, []Bundle{b}, []Receipt{badReceipt}, r.Execution); err == nil {
		t.Fatal("failed receipt accepted")
	}
	parent := clone(c)
	parent.ID = "parent"
	c.Prerequisites = []string{parent.ID}
	hash, _ := ContractDigest(c)
	b.Observation.Contract = hash
	b.Observation.Prerequisites = map[string]string{parent.ID: Digest(nil)}
	r.Contract = hash
	r.Observation = ObservationDigest(b.Observation)
	if err := Aggregate([]Contract{c, parent}, []Bundle{b}, []Receipt{r}, r.Execution); err == nil {
		t.Fatal("missing parent accepted")
	}
	p := clone(b)
	p.Observation.Contract, _ = ContractDigest(parent)
	p.Observation.Prerequisites = nil
	pr := clone(r)
	pr.Contract = p.Observation.Contract
	pr.Observation = ObservationDigest(p.Observation)
	if err := Aggregate([]Contract{c, parent}, []Bundle{b, p}, []Receipt{r, pr}, r.Execution); err == nil {
		t.Fatal("mixed prerequisite accepted")
	}
	b.Observation.Prerequisites[parent.ID] = pr.Observation
	r.Observation = ObservationDigest(b.Observation)
	if err := Aggregate([]Contract{c, parent}, []Bundle{b, p}, []Receipt{r, pr}, r.Execution); err != nil {
		t.Fatal(err)
	}
	if err := Aggregate(nil, nil, nil, r.Execution); err == nil {
		t.Fatal("empty catalog accepted")
	}
}
