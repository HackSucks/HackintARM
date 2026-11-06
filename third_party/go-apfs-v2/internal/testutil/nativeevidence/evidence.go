// Package nativeevidence validates independent native observations and current
// execution receipts. Historical provenance is never checked against a checkout.
package nativeevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"sort"
	"strings"
)

const Schema = 1

// Contract specifies the complete qualification obligation. IDs are stable
// logical names, not paths created on the receiving filesystem.
type Contract struct {
	Schema        int      `json:"schema"`
	ID            string   `json:"id"`
	Profiles      []string `json:"profiles"`
	Consumers     []string `json:"consumers"`
	Cases         []string `json:"cases"`
	Prerequisites []string `json:"prerequisites"`
	Comparator    string   `json:"comparator"`
}

// Execution describes this execution only. Native compiler and SDK identity
// belong to Capture, separately from the Go implementation's receipt.
type Execution struct {
	Repository string            `json:"repository"`
	Revision   string            `json:"revision"`
	Run        string            `json:"run"`
	Attempt    string            `json:"attempt"`
	Job        string            `json:"job"`
	Go         string            `json:"go"`
	Sources    map[string]string `json:"sources"`
}

type Capture struct {
	Profile     string            `json:"profile"`
	Environment map[string]string `json:"environment"`
	Sources     map[string]string `json:"sources"`
	Artifacts   map[string]string `json:"artifacts"`
}

// Case binds exact native inputs and outputs to content-addressed blobs.
// Filesystem metadata, sparse extents and raw names are encoded inside inputs.
type Case struct {
	ID     string `json:"id"`
	Input  string `json:"input"`
	Result string `json:"result"`
}

type Observation struct {
	Schema        int               `json:"schema"`
	Contract      string            `json:"contract"`
	Profile       string            `json:"profile"`
	Cases         []Case            `json:"cases"`
	Prerequisites map[string]string `json:"prerequisites"`
}

type Bundle struct {
	Schema      int         `json:"schema"`
	Observation Observation `json:"observation"`
	Capture     Capture     `json:"capture"`
	Execution   Execution   `json:"execution"`
	Complete    bool        `json:"complete"`
}

// Receipt records verification without inserting Go results into the oracle.
type Receipt struct {
	Schema      int               `json:"schema"`
	Contract    string            `json:"contract"`
	Observation string            `json:"observation"`
	Consumer    string            `json:"consumer"`
	Execution   Execution         `json:"execution"`
	Cases       map[string]string `json:"cases"`
	Artifacts   map[string]string `json:"artifacts"`
	Complete    bool              `json:"complete"`
}

func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}

func names(values []string) error {
	seen := map[string]bool{}
	for _, name := range values {
		if name == "" || strings.TrimSpace(name) != name || seen[name] {
			return fmt.Errorf("empty, invalid or duplicate identity %q", name)
		}
		seen[name] = true
	}
	return nil
}

func ValidateContract(c Contract) error {
	if c.Schema != Schema || c.ID == "" || c.Comparator == "" || len(c.Profiles) == 0 || len(c.Consumers) == 0 || len(c.Cases) == 0 {
		return fmt.Errorf("incomplete contract %q", c.ID)
	}
	for _, group := range [][]string{c.Profiles, c.Consumers, c.Cases, c.Prerequisites} {
		if err := names(group); err != nil {
			return err
		}
	}
	return nil
}

// ValidateCatalog rejects ambiguous ownership and dependency cycles before any
// expensive native producers are scheduled.
func ValidateCatalog(catalog []Contract) error {
	contracts := map[string]Contract{}
	for _, c := range catalog {
		if err := ValidateContract(c); err != nil {
			return err
		}
		if _, ok := contracts[c.ID]; ok {
			return fmt.Errorf("duplicate contract %s", c.ID)
		}
		contracts[c.ID] = c
	}
	if len(contracts) == 0 {
		return fmt.Errorf("empty catalog")
	}
	state := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		c, ok := contracts[id]
		if !ok {
			return fmt.Errorf("missing prerequisite %s", id)
		}
		if state[id] == 1 {
			return fmt.Errorf("cyclic prerequisite %s", id)
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, parent := range c.Prerequisites {
			if err := visit(parent); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for _, c := range catalog {
		if err := visit(c.ID); err != nil {
			return err
		}
	}
	return nil
}

func ContractDigest(c Contract) (string, error) {
	if err := ValidateContract(c); err != nil {
		return "", err
	}
	c.Profiles = append([]string(nil), c.Profiles...)
	c.Consumers = append([]string(nil), c.Consumers...)
	c.Cases = append([]string(nil), c.Cases...)
	c.Prerequisites = append([]string(nil), c.Prerequisites...)
	sort.Strings(c.Profiles)
	sort.Strings(c.Consumers)
	sort.Strings(c.Cases)
	sort.Strings(c.Prerequisites)
	b, _ := json.Marshal(c)
	return Digest(b), nil
}

// ObservationDigest intentionally excludes capture/execution provenance.
func ObservationDigest(o Observation) string {
	o.Cases = append([]Case(nil), o.Cases...)
	sort.Slice(o.Cases, func(i, j int) bool { return o.Cases[i].ID < o.Cases[j].ID })
	b, _ := json.Marshal(o)
	return Digest(b)
}

func sameExecution(actual, expected Execution) error {
	if actual.Repository == "" || actual.Revision == "" || actual.Run == "" || actual.Attempt == "" || actual.Job == "" || actual.Go == "" || len(actual.Sources) == 0 {
		return fmt.Errorf("incomplete execution provenance")
	}
	for name, hash := range actual.Sources {
		if !fs.ValidPath(name) || !validDigest(hash) {
			return fmt.Errorf("invalid execution source %q", name)
		}
	}
	if actual.Repository != expected.Repository || actual.Revision != expected.Revision || actual.Run != expected.Run || actual.Attempt != expected.Attempt {
		return fmt.Errorf("mixed repository, revision, run or attempt")
	}
	if actual.Go != expected.Go || !reflect.DeepEqual(actual.Sources, expected.Sources) {
		return fmt.Errorf("mixed current toolchain or checkout sources")
	}
	return nil
}

func verifyBlobs(ctx context.Context, store fs.FS, hashes map[string]string) error {
	for name, hash := range hashes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == "" || !validDigest(hash) {
			return fmt.Errorf("invalid content identity %q", name)
		}
		f, err := store.Open("blobs/" + hash)
		if err != nil {
			return fmt.Errorf("missing original bytes %s: %w", name, err)
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, contextReader{ctx, f})
		closeErr := f.Close()
		if copyErr != nil {
			return fmt.Errorf("reading original bytes %s: %w", name, copyErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(h.Sum(nil)) != hash {
			return fmt.Errorf("corrupted original bytes %s", name)
		}
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

// VerifyBundle checks original archived bytes. expected is nil only when
// validating retained historical evidence; fresh CI always supplies it.
func VerifyBundle(ctx context.Context, store fs.FS, c Contract, b Bundle, expected *Execution) error {
	hash, err := ContractDigest(c)
	if err != nil {
		return err
	}
	if b.Schema != Schema || b.Observation.Schema != Schema || !b.Complete || b.Observation.Contract != hash {
		return fmt.Errorf("incomplete or incompatible native bundle")
	}
	if b.Capture.Profile != b.Observation.Profile || !contains(c.Profiles, b.Observation.Profile) {
		return fmt.Errorf("wrong native profile %s", b.Observation.Profile)
	}
	major := strings.TrimPrefix(b.Observation.Profile, "macos")
	if (major != "15" && major != "26" && major != "27") || !strings.HasPrefix(b.Capture.Environment["os_version"], major+".") {
		return fmt.Errorf("native OS does not match profile %s", b.Observation.Profile)
	}
	for _, name := range []string{"os_version", "os_build", "architecture", "compiler", "sdk"} {
		if b.Capture.Environment[name] == "" {
			return fmt.Errorf("missing native environment %s", name)
		}
	}
	if len(b.Capture.Sources) == 0 || len(b.Capture.Artifacts) == 0 {
		return fmt.Errorf("missing capture provenance")
	}
	if expected != nil {
		if err = sameExecution(b.Execution, *expected); err != nil {
			return err
		}
	}
	if err = sameExecution(b.Execution, b.Execution); err != nil {
		return err
	}
	if len(b.Observation.Prerequisites) != len(c.Prerequisites) {
		return fmt.Errorf("incomplete prerequisite inventory")
	}
	for _, id := range c.Prerequisites {
		if !validDigest(b.Observation.Prerequisites[id]) {
			return fmt.Errorf("missing prerequisite observation %s", id)
		}
	}
	if len(b.Observation.Cases) != len(c.Cases) {
		return fmt.Errorf("incomplete native case inventory")
	}
	seen := map[string]bool{}
	inputs := map[string]string{}
	for _, item := range b.Observation.Cases {
		if seen[item.ID] || !contains(c.Cases, item.ID) {
			return fmt.Errorf("unexpected or duplicate native case %s", item.ID)
		}
		seen[item.ID] = true
		inputs[item.ID+"/input"] = item.Input
		inputs[item.ID+"/result"] = item.Result
	}
	// Execution source hashes are checked against the receiving checkout above.
	// Only the independent native oracle's original inputs belong to its blob
	// archive; current Go verification inputs do not become oracle prerequisites.
	for _, group := range []map[string]string{inputs, b.Capture.Sources, b.Capture.Artifacts} {
		if err = verifyBlobs(ctx, store, group); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

// VerifyReceipt requires every case to pass against this exact independent
// observation. A current Go output can never become a native expected result.
func VerifyReceipt(c Contract, b Bundle, r Receipt, expected Execution) error {
	hash, err := ContractDigest(c)
	if err != nil {
		return err
	}
	if !b.Complete || b.Observation.Contract != hash || !contains(c.Profiles, b.Observation.Profile) || !contains(c.Consumers, r.Consumer) || r.Schema != Schema || !r.Complete || r.Contract != hash || r.Observation != ObservationDigest(b.Observation) {
		return fmt.Errorf("incomplete or incompatible verification receipt")
	}
	if err = sameExecution(r.Execution, expected); err != nil {
		return err
	}
	if len(r.Artifacts) == 0 {
		return fmt.Errorf("missing Go verification artifacts")
	}
	for name, hash := range r.Artifacts {
		if !fs.ValidPath(name) || !validDigest(hash) {
			return fmt.Errorf("invalid Go verification artifact %q", name)
		}
	}
	if len(r.Cases) != len(c.Cases) {
		return fmt.Errorf("incomplete verification inventory")
	}
	for _, id := range c.Cases {
		if r.Cases[id] != "pass" {
			return fmt.Errorf("missing, skipped or failed verification %s", id)
		}
	}
	return nil
}

// Difference lists only native behavior/input changes. Provenance changes are
// separately reviewable and do not affect the semantic identity.
type Difference struct {
	Case string `json:"case"`
	Kind string `json:"kind"`
}

func Compare(previous, current Observation) ([]Difference, error) {
	if previous.Contract != current.Contract || previous.Profile != current.Profile || previous.Schema != Schema || current.Schema != Schema {
		return nil, fmt.Errorf("incompatible observation contract or profile")
	}
	if !reflect.DeepEqual(previous.Prerequisites, current.Prerequisites) {
		return nil, fmt.Errorf("changed prerequisite observations")
	}
	old, fresh := map[string]Case{}, map[string]Case{}
	for _, pair := range []struct {
		items  []Case
		target map[string]Case
	}{{previous.Cases, old}, {current.Cases, fresh}} {
		for _, item := range pair.items {
			if _, ok := pair.target[item.ID]; ok || item.ID == "" || !validDigest(item.Input) || !validDigest(item.Result) {
				return nil, fmt.Errorf("invalid comparison case %s", item.ID)
			}
			pair.target[item.ID] = item
		}
	}
	var diff []Difference
	for id, item := range old {
		other, ok := fresh[id]
		if !ok {
			diff = append(diff, Difference{id, "removed"})
			continue
		}
		if item.Input != other.Input {
			diff = append(diff, Difference{id, "input"})
		}
		if item.Result != other.Result {
			diff = append(diff, Difference{id, "result"})
		}
	}
	for id := range fresh {
		if _, ok := old[id]; !ok {
			diff = append(diff, Difference{id, "added"})
		}
	}
	sort.Slice(diff, func(i, j int) bool {
		if diff[i].Case == diff[j].Case {
			return diff[i].Kind < diff[j].Kind
		}
		return diff[i].Case < diff[j].Case
	})
	return diff, nil
}

// Aggregate fails closed when any required producer/consumer is missing. All
// supplied bundles must have been verified before calling this gate.
func Aggregate(catalog []Contract, bundles []Bundle, receipts []Receipt, expected Execution) error {
	if err := ValidateCatalog(catalog); err != nil {
		return err
	}
	contracts := map[string]Contract{}
	for _, c := range catalog {
		hash, _ := ContractDigest(c)
		contracts[hash] = c
	}
	observations := map[string]Bundle{}
	ids := map[string]string{}
	for _, b := range bundles {
		c, ok := contracts[b.Observation.Contract]
		if !ok {
			return fmt.Errorf("unexpected producer contract")
		}
		key := c.ID + "/" + b.Observation.Profile
		if _, ok := observations[key]; ok {
			return fmt.Errorf("duplicate producer %s", key)
		}
		if !b.Complete || !contains(c.Profiles, b.Observation.Profile) {
			return fmt.Errorf("incomplete or unexpected producer %s", key)
		}
		if err := sameExecution(b.Execution, expected); err != nil {
			return err
		}
		observations[key] = b
		ids[ObservationDigest(b.Observation)] = key
	}
	verified := map[string]bool{}
	for _, r := range receipts {
		key, ok := ids[r.Observation]
		consumerKey := key + "/" + r.Consumer
		if !ok || verified[consumerKey] {
			return fmt.Errorf("unexpected or duplicate consumer %s", key)
		}
		b := observations[key]
		if err := VerifyReceipt(contracts[b.Observation.Contract], b, r, expected); err != nil {
			return err
		}
		verified[consumerKey] = true
	}
	for _, c := range catalog {
		for _, profile := range c.Profiles {
			key := c.ID + "/" + profile
			b, ok := observations[key]
			if !ok {
				return fmt.Errorf("missing qualification %s", key)
			}
			for _, consumer := range c.Consumers {
				if !verified[key+"/"+consumer] {
					return fmt.Errorf("missing qualification %s/%s", key, consumer)
				}
			}
			for _, parent := range c.Prerequisites {
				parentKey := parent + "/" + profile
				p, ok := observations[parentKey]
				if !ok || b.Observation.Prerequisites[parent] != ObservationDigest(p.Observation) {
					return fmt.Errorf("missing or mixed prerequisite %s", parentKey)
				}
			}
		}
	}
	return nil
}
