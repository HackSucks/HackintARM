package cirunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCommandHelper(t *testing.T) {
	mode := os.Getenv("CIRUNNER_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "json-diagnostics":
		fmt.Fprintln(os.Stdout, `{"Action":"pass"}`)
		fmt.Fprintln(os.Stderr, "go: downloading fixture.invalid/module v1.0.0")
	case "bytes":
		fmt.Fprint(os.Stdout, "out\x00\xff\n")
		fmt.Fprint(os.Stderr, "err\x00\xfe\n")
	case "exit":
		fmt.Fprint(os.Stdout, "partial")
		fmt.Fprint(os.Stderr, strings.Repeat("abcdefgh", 20000))
		os.Exit(7)
	case "json":
		fmt.Fprintln(os.Stdout, `{"Action":"run","Package":"fixture","Test":"TestLive"}`)
		_, _ = io.Copy(io.Discard, os.Stdin)
		fmt.Fprintln(os.Stdout, `{"Action":"pass","Package":"fixture","Test":"TestLive"}`)
	case "hold":
		time.Sleep(30 * time.Second)
	case "descendant":
		cmd := exec.Command(os.Args[0], "-test.run=^TestCommandHelper$")
		cmd.Env = append(withoutHelper(os.Environ()), "CIRUNNER_HELPER=hold")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			os.Exit(8)
		}
		fmt.Fprintln(os.Stdout, cmd.Process.Pid)
	default:
		os.Exit(9)
	}
	os.Exit(0)
}

func withoutHelper(env []string) []string {
	var out []string
	for _, s := range env {
		if !strings.HasPrefix(s, "CIRUNNER_HELPER=") {
			out = append(out, s)
		}
	}
	return out
}

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *synchronizedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

func testReporter(t *testing.T) (*Reporter, *synchronizedBuffer) {
	t.Helper()
	t.Setenv("APFS_CI_STRICT_REPORTING", "")
	b := &synchronizedBuffer{}
	r := NewReporter(b, 256)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := r.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return r, b
}
func helper(t *testing.T, mode string, reporter *Reporter) *Cmd {
	t.Helper()
	c := CommandContext(t.Context(), os.Args[0], "-test.run=^TestCommandHelper$")
	c.Env = append(withoutHelper(os.Environ()), "CIRUNNER_HELPER="+mode)
	c.Options = Options{Reporter: reporter, Label: mode, Heartbeat: 5 * time.Millisecond}
	return c
}
func flush(t *testing.T, r *Reporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}
func waitText(t *testing.T, b *synchronizedBuffer, text string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if strings.Contains(b.String(), text) {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("missing %q in %s", text, b.String())
		case <-tick.C:
		}
	}
}

func TestRawOutputAndErrorsMatchExec(t *testing.T) {
	r, b := testReporter(t)
	for _, mode := range []string{"bytes", "exit"} {
		for _, combined := range []bool{false, true} {
			t.Run(fmt.Sprint(mode, combined), func(t *testing.T) {
				c := helper(t, mode, r)
				native := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCommandHelper$")
				native.Env = c.Env
				var got, want []byte
				var ge, we error
				if combined {
					got, ge = c.CombinedOutput()
					want, we = native.CombinedOutput()
				} else {
					got, ge = c.Output()
					want, we = native.Output()
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("raw bytes differ: %d/%d", len(got), len(want))
				}
				var gx, wx *exec.ExitError
				if errors.As(ge, &gx) != errors.As(we, &wx) {
					t.Fatalf("errors %v/%v", ge, we)
				}
				if gx != nil && (gx.ExitCode() != wx.ExitCode() || !bytes.Equal(gx.Stderr, wx.Stderr)) {
					t.Fatal("exit status/stderr excerpt changed")
				}
			})
		}
	}
	flush(t, r)
	if strings.Contains(b.String(), "abcdefgh") || strings.Contains(b.String(), "out\x00") {
		t.Fatal("raw output leaked to console")
	}
}

func TestRunStartWaitAndInvalidCalls(t *testing.T) {
	r, _ := testReporter(t)
	c := helper(t, "bytes", r)
	var out, stderr bytes.Buffer
	c.Stdout = &out
	c.Stderr = &stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err == nil {
		t.Fatal("second Start accepted")
	}
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err == nil {
		t.Fatal("second Wait accepted")
	}
	if out.String() != "out\x00\xff\n" || stderr.String() != "err\x00\xfe\n" {
		t.Fatal("custom sinks changed")
	}
	if err := helper(t, "bytes", r).Wait(); err == nil {
		t.Fatal("unstarted Wait accepted")
	}
	for _, method := range []string{"output", "combined"} {
		c := helper(t, "bytes", r)
		c.Stdout = io.Discard
		var err error
		if method == "output" {
			_, err = c.Output()
		} else {
			_, err = c.CombinedOutput()
		}
		if err == nil || err.Error() != "exec: Stdout already set" {
			t.Fatal(err)
		}
	}
	c = helper(t, "bytes", r)
	c.Stderr = io.Discard
	if _, err := c.CombinedOutput(); err == nil || err.Error() != "exec: Stderr already set" {
		t.Fatal(err)
	}
	c = helper(t, "exit", r)
	c.Stderr = io.Discard
	_, err := c.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || len(exit.Stderr) != 0 {
		t.Fatal("caller stderr replaced", err)
	}
	c = Command(filepath.Join(t.TempDir(), "missing"))
	c.Options.Reporter = r
	if err := c.Run(); err == nil {
		t.Fatal("missing command started")
	}
	if err := c.Wait(); err == nil {
		t.Fatal("failed start wait accepted")
	}
}

func TestLiveJSONBeforeChildExitAndPipeProtocol(t *testing.T) {
	r, b := testReporter(t)
	c := helper(t, "json", r)
	c.Options.JSONProgress = true
	in, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	c.Stdout = &raw
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	waitText(t, b, "test=\"TestLive\"")
	waitText(t, b, "ACTIVITY")
	if strings.Contains(b.String(), "FINISH") {
		t.Fatal("child unexpectedly exited before release")
	}
	if err = in.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.Wait(); err != nil {
		t.Fatal(err)
	}
	flush(t, r)
	if !strings.Contains(raw.String(), `"Action":"pass"`) || !strings.Contains(b.String(), "action=pass") {
		t.Fatal("final progress/raw output lost")
	}
	// The original StdoutPipe remains an inherited *os.File, never wrapped.
	c = helper(t, "bytes", r)
	pipe, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c.Options.JSONProgress = true
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	rawBytes, err := io.ReadAll(pipe)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Wait(); err != nil {
		t.Fatal(err)
	}
	if string(rawBytes) != "out\x00\xff\n" {
		t.Fatal("pipe bytes changed")
	}
}

func TestCancellationReportedBeforeBlockedWait(t *testing.T) {
	r, b := testReporter(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := CommandContext(ctx, os.Args[0], "-test.run=^TestCommandHelper$")
	c.Env = append(withoutHelper(os.Environ()), "CIRUNNER_HELPER=hold")
	c.Options = Options{Reporter: r, Heartbeat: 5 * time.Millisecond}
	entered, release := make(chan struct{}), make(chan struct{})
	c.Cancel = func() error { close(entered); <-release; return c.Process.Kill() }
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	cancel()
	<-entered
	waitText(t, b, "CANCEL")
	select {
	case err := <-done:
		t.Fatalf("Wait escaped held cancellation: %v", err)
	default:
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("cancelled process succeeded")
	}
	flush(t, r)
	if strings.Count(b.String(), "CANCEL") != 1 {
		t.Fatal("cancellation duplicated")
	}
	ctx2, cancel2 := context.WithCancel(t.Context())
	cancel2()
	c = CommandContext(ctx2, os.Args[0])
	c.Options.Reporter = r
	if err := c.Run(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRegularFileSinkDoesNotWaitForDescendant(t *testing.T) {
	r, _ := testReporter(t)
	file, err := os.CreateTemp(t.TempDir(), "raw")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	c := helper(t, "descendant", r)
	c.Options.JSONProgress = true
	c.Stdout = file
	c.Stderr = file
	start := time.Now()
	if err = c.Run(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("waited for inherited descendant handles")
	}
	if c.Stdout != file || c.Stderr != file {
		t.Fatal("file converted into pipe")
	}
	b, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = p.Wait()
}

func TestFileProgressIsLiveAndRawPreserved(t *testing.T) {
	r, b := testReporter(t)
	f, err := os.CreateTemp(t.TempDir(), "json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := helper(t, "json", r)
	c.Options.JSONProgress = true
	c.Stdout = f
	in, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	waitText(t, b, "action=run")
	if err = in.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.Wait(); err != nil {
		t.Fatal(err)
	}
	if c.Stdout != f {
		t.Fatal("changed raw descriptor")
	}
	raw, err := os.ReadFile(f.Name())
	if err != nil || !bytes.Contains(raw, []byte(`"Action":"pass"`)) {
		t.Fatal("raw file", err)
	}
	if !strings.Contains(b.String(), "action=pass") {
		t.Fatal("final file progress was not drained")
	}
}

func TestCallerWaitDelayAndCopyErrorsArePreserved(t *testing.T) {
	r, _ := testReporter(t)
	c := helper(t, "descendant", r)
	c.WaitDelay = 20 * time.Millisecond
	raw, err := c.Output()
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatal("inherited pipe wait error changed", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = p.Wait()
	c = helper(t, "bytes", r)
	c.Stdout = errorWriter{err: io.ErrClosedPipe}
	if err = c.Run(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("raw output copy failure hidden", err)
	}
}

func TestGoJSONDetection(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want bool
	}{
		{"go", []string{"test", "-json", "./..."}, true}, {"go.exe", []string{"test", "-json=true"}, true}, {"go", []string{"tool", "test2json"}, true}, {"go", nil, false}, {"go", []string{"test"}, false}, {"go", []string{"build"}, false}, {"clang", []string{"-json"}, false},
	} {
		c := Command(test.name, test.args...)
		c.Path = test.name
		if c.jsonProgress() != test.want {
			t.Fatalf("%+v", test)
		}
	}
}

func TestExcerptChunkBoundaries(t *testing.T) {
	for _, size := range []int{0, 10, 32768, 32769, 65536, 65537, 100000} {
		var e excerpt
		all := bytes.Repeat([]byte("0123456789"), size/10+1)
		all = all[:size]
		for p := all; len(p) > 0; {
			n := min(777, len(p))
			_, _ = e.Write(p[:n])
			p = p[n:]
		}
		want := all
		if size > 65536 {
			want = append(append(append([]byte{}, all[:32768]...), []byte(fmt.Sprintf("\n... omitting %d bytes ...\n", size-65536))...), all[size-32768:]...)
		}
		if !bytes.Equal(e.bytes(), want) {
			t.Fatal("excerpt size", size)
		}
	}
}
