package cirunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJSONObserverPreservesRawBoundariesAndSuppressesBulk(t *testing.T) {
	r, b := testReporter(t)
	var out bytes.Buffer
	o := &jsonObserver{writer: &out, reporter: r, label: "oracle"}
	var input bytes.Buffer
	input.WriteString("{bad}\n{\"Action\":\"unknown\"}\n")
	input.WriteString(strings.Repeat("binary", 12000) + "\n")
	raw, err := json.Marshal(map[string]string{"Action": "output", "Package": "p", "Test": "T", "Output": strings.Repeat("x", 1000)})
	if err != nil {
		t.Fatal(err)
	}
	input.Write(append(raw, '\n'))
	input.WriteString("{\"Action\":\"pass\",\"Test\":\"T\"}\n")
	all := append([]byte(nil), input.Bytes()...)
	for p := all; len(p) > 0; {
		n := min(79, len(p))
		if _, err = o.Write(p[:n]); err != nil {
			t.Fatal(err)
		}
		p = p[n:]
	}
	o.flush()
	flush(t, r)
	if !bytes.Equal(all, out.Bytes()) {
		t.Fatal("raw changed")
	}
	log := b.String()
	if !strings.Contains(log, "action=pass") || !strings.Contains(log, "console excerpt; raw retained") || strings.Contains(log, "binary") || strings.Contains(log, "unknown") {
		t.Fatal(log)
	}
	sentinel := errors.New("raw sink failed")
	o.writer = errorWriter{err: sentinel}
	if n, err := o.Write([]byte("content")); n != 0 || !errors.Is(err, sentinel) {
		t.Fatal(n, err)
	}
}

type sliceWriter []byte

func (w sliceWriter) Write(p []byte) (int, error) { return len(p), nil }
func TestWriterIdentityAndCombinedJSON(t *testing.T) {
	if sameWriter(sliceWriter{}, sliceWriter{}) || sameWriter(nil, io.Discard) || sameWriter(io.Discard, nil) {
		t.Fatal("invalid shared sink")
	}
	r, b := testReporter(t)
	c := helper(t, "json", r)
	c.Options.JSONProgress = true
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	flush(t, r)
	if !bytes.Contains(out, []byte(`"Action":"pass"`)) || !strings.Contains(b.String(), "action=pass") {
		t.Fatal("combined progress missing")
	}
}

func TestTailClosedMissingReplacedAndNonRegular(t *testing.T) {
	r, b := testReporter(t)
	makeCommand := func() *Cmd { c := Command("fixture"); c.Options.Reporter = r; c.begin(); return c }
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	c := makeCommand()
	c.tail(f)
	c.finish(nil)
	f = createMovableFile(t, filepath.Join(t.TempDir(), "missing"))
	defer f.Close()
	if err = os.Rename(f.Name(), f.Name()+"-held"); err != nil {
		t.Fatal(err)
	}
	c = makeCommand()
	c.tail(f)
	c.finish(nil)
	flush(t, r)
	if !strings.Contains(b.String(), "progress unavailable") {
		t.Fatal(b.String())
	}
	f = createMovableFile(t, filepath.Join(t.TempDir(), "replaced"))
	defer f.Close()
	if err = os.Rename(f.Name(), f.Name()+"-old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Name(), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	c = makeCommand()
	c.tail(f)
	c.finish(nil)
	flush(t, r)
	if !strings.Contains(b.String(), "identity changed") {
		t.Fatal(b.String())
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	c = makeCommand()
	c.tail(dir)
	c.finish(nil)
	// A complete large regular-file scan exercises chunk boundaries, and the
	// command's lifecycle still ends independently from the tail worker.
	f, err = os.Create(filepath.Join(t.TempDir(), "bulk"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.WriteString(strings.Repeat("x", 70000) + "\n{\"Action\":\"run\",\"Test\":\"tail\"}\n"); err != nil {
		t.Fatal(err)
	}
	c = makeCommand()
	done := make(chan struct{})
	go func() { c.tail(f); close(done) }()
	waitText(t, b, "test=\"tail\"")
	c.finish(nil)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tail leaked")
	}
}

func TestStartupMonitoringIndependentOfBlockingPreparation(t *testing.T) {
	r, b := testReporter(t)
	c := CommandContext(context.Background(), "fixture")
	c.Options = Options{Reporter: r, Heartbeat: time.Millisecond}
	c.begin()
	c.begin()
	waitText(t, b, "pid=0")
	c.finish(errors.New("startup fixture failure"))
	flush(t, r)
	if strings.Count(b.String(), "START command") != 1 || !strings.Contains(b.String(), "startup fixture failure") {
		t.Fatal(b.String())
	}
}

func TestStrictCommandFailsMissingProgressFile(t *testing.T) {
	r, _ := testReporter(t)
	f := createMovableFile(t, filepath.Join(t.TempDir(), "removed"))
	var err error
	defer f.Close()
	if err = os.Rename(f.Name(), f.Name()+"-held"); err != nil {
		t.Fatal(err)
	}
	c := helper(t, "json", r)
	c.Options.JSONProgress = true
	c.Options.StrictReporting = true
	c.Stdout = f
	if err = c.Run(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing progress silently accepted", err)
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	if err != nil || !bytes.Contains(raw, []byte(`"Action":"pass"`)) {
		t.Fatal("raw child output changed", err)
	}
}
