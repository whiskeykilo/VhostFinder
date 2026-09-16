package utils

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// rcBaseOptions returns a fresh Options with representative field values for
// the pieces Fingerprint hashes. Each call returns an independent value so
// tests can mutate a copy without affecting others.
func rcBaseOptions() *Options {
	return &Options{
		Targets: []Target{
			{Host: "10.0.0.1", Port: 80, TLS: false},
			{Host: "10.0.0.2", Port: 443, TLS: true},
		},
		Paths:    []string{"/", "/admin"},
		Domains:  []string{"a.example.com", "b.example.com"},
		Wordlist: []string{"foo", "bar", "baz"},
	}
}

func TestFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("stable across calls for identical Options", func(t *testing.T) {
		t.Parallel()
		a := Fingerprint(rcBaseOptions())
		b := Fingerprint(rcBaseOptions())
		if a != b {
			t.Errorf("Fingerprint differs across two structurally-identical Options: %q != %q", a, b)
		}
		// Calling it again on the very same pointer must also be stable.
		opts := rcBaseOptions()
		if got, want := Fingerprint(opts), Fingerprint(opts); got != want {
			t.Errorf("Fingerprint is not stable across repeated calls: %q != %q", got, want)
		}
	})

	base := Fingerprint(rcBaseOptions())

	t.Run("differs when Targets change", func(t *testing.T) {
		t.Parallel()
		opts := rcBaseOptions()
		opts.Targets = append(opts.Targets, Target{Host: "10.0.0.3", Port: 8080, TLS: false})
		if got := Fingerprint(opts); got == base {
			t.Errorf("Fingerprint unchanged after modifying Targets: %q", got)
		}
	})

	t.Run("differs when Paths change", func(t *testing.T) {
		t.Parallel()
		opts := rcBaseOptions()
		opts.Paths = append(opts.Paths, "/new-path")
		if got := Fingerprint(opts); got == base {
			t.Errorf("Fingerprint unchanged after modifying Paths: %q", got)
		}
	})

	t.Run("differs when Domains change", func(t *testing.T) {
		t.Parallel()
		opts := rcBaseOptions()
		opts.Domains = append(opts.Domains, "c.example.com")
		if got := Fingerprint(opts); got == base {
			t.Errorf("Fingerprint unchanged after modifying Domains: %q", got)
		}
	})

	t.Run("differs when Wordlist changes", func(t *testing.T) {
		t.Parallel()
		opts := rcBaseOptions()
		opts.Wordlist = append(opts.Wordlist, "qux")
		if got := Fingerprint(opts); got == base {
			t.Errorf("Fingerprint unchanged after modifying Wordlist: %q", got)
		}
	})

	t.Run("unaffected fields do not change the fingerprint", func(t *testing.T) {
		t.Parallel()
		opts := rcBaseOptions()
		opts.Threshold = 0.9
		opts.Threads = 500
		opts.Silent = true
		if got := Fingerprint(opts); got != base {
			t.Errorf("Fingerprint changed after modifying fields it does not hash: %q != %q", got, base)
		}
	})
}

func TestOpenCheckpointEmptyPath(t *testing.T) {
	t.Parallel()
	c, err := OpenCheckpoint("", "some-fingerprint")
	if err != nil {
		t.Fatalf("OpenCheckpoint(\"\", ...) error = %v, want nil", err)
	}
	if c != nil {
		t.Fatalf("OpenCheckpoint(\"\", ...) = %+v, want nil", c)
	}
}

func TestNilCheckpointIsSafe(t *testing.T) {
	t.Parallel()
	var c *Checkpoint

	if got := c.Done(Target{Host: "h", Port: 80}, "/", "d.example.com"); got != false {
		t.Errorf("nil Checkpoint.Done() = %v, want false", got)
	}
	if err := c.Record(Target{Host: "h", Port: 80}, "/", "d.example.com"); err != nil {
		t.Errorf("nil Checkpoint.Record() error = %v, want nil", err)
	}
	if got := c.Completed(); got != 0 {
		t.Errorf("nil Checkpoint.Completed() = %d, want 0", got)
	}
	if err := c.Close(); err != nil {
		t.Errorf("nil Checkpoint.Close() error = %v, want nil", err)
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoint.txt")
	fingerprint := Fingerprint(rcBaseOptions())

	c, err := OpenCheckpoint(path, fingerprint)
	if err != nil {
		t.Fatalf("OpenCheckpoint (fresh) error = %v", err)
	}
	if got := c.Completed(); got != 0 {
		t.Fatalf("fresh Checkpoint.Completed() = %d, want 0", got)
	}

	t1 := Target{Host: "10.0.0.1", Port: 80, TLS: false}
	t2 := Target{Host: "10.0.0.2", Port: 443, TLS: true}

	recorded := []struct {
		target Target
		path   string
		domain string
	}{
		{t1, "/", "a.example.com"},
		{t1, "/admin", "a.example.com"},
		{t2, "/", "b.example.com"},
	}
	for _, r := range recorded {
		if err := c.Record(r.target, r.path, r.domain); err != nil {
			t.Fatalf("Record(%v, %q, %q) error = %v", r.target, r.path, r.domain, err)
		}
	}

	// Record buffers: nothing recorded in this same handle should already
	// report as done until the writer is flushed via Close and reopened.
	if c.Done(t1, "/", "a.example.com") {
		t.Errorf("Done() reported true for a job recorded in this run before Close/reopen")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	c2, err := OpenCheckpoint(path, fingerprint)
	if err != nil {
		t.Fatalf("OpenCheckpoint (reopen, same fingerprint) error = %v", err)
	}
	defer c2.Close()

	if got, want := c2.Completed(), len(recorded); got != want {
		t.Errorf("Completed() = %d, want %d", got, want)
	}
	for _, r := range recorded {
		if !c2.Done(r.target, r.path, r.domain) {
			t.Errorf("Done(%v, %q, %q) = false, want true (was recorded)", r.target, r.path, r.domain)
		}
	}

	notRecorded := []struct {
		target Target
		path   string
		domain string
	}{
		{t2, "/admin", "b.example.com"},
		{t1, "/", "b.example.com"},
		{Target{Host: "10.0.0.9", Port: 80}, "/", "a.example.com"},
	}
	for _, r := range notRecorded {
		if c2.Done(r.target, r.path, r.domain) {
			t.Errorf("Done(%v, %q, %q) = true, want false (was never recorded)", r.target, r.path, r.domain)
		}
	}
}

func TestOpenCheckpointDifferentFingerprintDoesNotTruncate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoint.txt")
	fingerprint := Fingerprint(rcBaseOptions())

	c, err := OpenCheckpoint(path, fingerprint)
	if err != nil {
		t.Fatalf("OpenCheckpoint (fresh) error = %v", err)
	}
	tgt := Target{Host: "10.0.0.1", Port: 80}
	if err := c.Record(tgt, "/", "a.example.com"); err != nil {
		t.Fatalf("Record error = %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	// Opening with a fingerprint for a different scan must fail...
	_, err = OpenCheckpoint(path, "a-totally-different-fingerprint")
	if err == nil {
		t.Fatal("OpenCheckpoint with mismatched fingerprint: want error, got nil")
	}
	if !strings.Contains(err.Error(), "different scan") {
		t.Errorf("error = %q, want it to mention a different scan", err.Error())
	}

	// ...and must not have truncated or otherwise damaged the file: the
	// original data is still readable under its real fingerprint.
	c2, err := OpenCheckpoint(path, fingerprint)
	if err != nil {
		t.Fatalf("OpenCheckpoint (correct fingerprint, after failed mismatched open) error = %v", err)
	}
	defer c2.Close()
	if got := c2.Completed(); got != 1 {
		t.Errorf("Completed() after failed mismatched reopen = %d, want 1 (file was not truncated)", got)
	}
	if !c2.Done(tgt, "/", "a.example.com") {
		t.Error("previously recorded job lost after failed mismatched reopen")
	}
}

func TestOpenCheckpointBadHeader(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoint.txt")
	if err := os.WriteFile(path, []byte("this is not a checkpoint file\nsome other content\n"), 0o600); err != nil {
		t.Fatalf("WriteFile setup error = %v", err)
	}

	_, err := OpenCheckpoint(path, Fingerprint(rcBaseOptions()))
	if err == nil {
		t.Fatal("OpenCheckpoint on a file without the checkpoint header: want error, got nil")
	}
	if !strings.Contains(err.Error(), "not a VhostFinder checkpoint") {
		t.Errorf("error = %q, want it to say the file is not a VhostFinder checkpoint", err.Error())
	}
}

func TestCheckpointConcurrentRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoint.txt")
	fingerprint := Fingerprint(rcBaseOptions())

	c, err := OpenCheckpoint(path, fingerprint)
	if err != nil {
		t.Fatalf("OpenCheckpoint error = %v", err)
	}

	const n = 200
	tgt := Target{Host: "10.0.0.1", Port: 80}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			domain := "d" + strconv.Itoa(i) + ".example.com"
			if err := c.Record(tgt, "/", domain); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Record error: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	c2, err := OpenCheckpoint(path, fingerprint)
	if err != nil {
		t.Fatalf("OpenCheckpoint (reopen) error = %v", err)
	}
	defer c2.Close()

	if got := c2.Completed(); got != n {
		t.Errorf("Completed() after %d concurrent Record calls = %d, want %d", n, got, n)
	}
}
