package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPermuteDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		wordlist []string
		domains  []string
		want     []string
	}{
		{
			name:     "no domain uses the wordlist as-is",
			wordlist: []string{"a.example.com", "b.example.com"},
			want:     []string{"a.example.com", "b.example.com"},
		},
		{
			name:     "one domain is appended to each prefix",
			wordlist: []string{"admin", "staging"},
			domains:  []string{"example.com"},
			want:     []string{"admin.example.com", "staging.example.com"},
		},
		{
			name:     "every prefix is crossed with every domain",
			wordlist: []string{"admin", "dev"},
			domains:  []string{"one.com", "two.net"},
			want:     []string{"admin.one.com", "admin.two.net", "dev.one.com", "dev.two.net"},
		},
		{
			name:     "blank entries are dropped",
			wordlist: []string{"admin", "", "   ", "dev"},
			domains:  []string{"example.com"},
			want:     []string{"admin.example.com", "dev.example.com"},
		},
		{
			name:     "duplicates collapse",
			wordlist: []string{"admin", "admin"},
			domains:  []string{"example.com"},
			want:     []string{"admin.example.com"},
		},
		{
			name:     "a trailing dot is trimmed",
			wordlist: []string{"admin.example.com."},
			want:     []string{"admin.example.com"},
		},
		{
			name:     "a blank domain is ignored",
			wordlist: []string{"admin"},
			domains:  []string{"example.com", ""},
			want:     []string{"admin.example.com"},
		},
		{
			name:     "an empty wordlist yields nothing",
			wordlist: nil,
			domains:  []string{"example.com"},
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := PermuteDomains(tc.wordlist, tc.domains)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// vhostServer serves distinct content for the named virtual hosts and a common
// 404 for everything else, which is the shape a real scan is looking for.
func vhostServer(t *testing.T, known map[string]string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if idx := strings.IndexByte(host, ':'); idx >= 0 {
			host = host[:idx]
		}
		if body, ok := known[host]; ok {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 - the requested site is not configured here</body></html>"))
	}))
	t.Cleanup(server.Close)

	return server
}

// runScan executes a scan against a server and returns the results it wrote.
func runScan(t *testing.T, server *httptest.Server, mutate func(*Options)) ([]Result, *Stats) {
	t.Helper()

	outPath := filepath.Join(t.TempDir(), "results.jsonl")
	reporter, err := NewReporter(outPath, FormatJSONL, true, false)
	if err != nil {
		t.Fatalf("new reporter: %v", err)
	}

	opts := testOptions()
	opts.Tls = false
	opts.Targets = []Target{testTarget(t, server, false)}
	opts.Paths = []string{"/"}
	opts.Threads = 4
	opts.MaxErrors = DefaultMaxErrors
	if mutate != nil {
		mutate(opts)
	}

	stats, err := EnumerateVhosts(context.Background(), opts, reporter)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if err := reporter.Close(); err != nil {
		t.Fatalf("close reporter: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}

	var results []Result
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var r Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decode result %q: %v", line, err)
		}
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Vhost < results[j].Vhost })

	return results, stats
}

func TestEnumerateVhostsFindsConfiguredHosts(t *testing.T) {
	t.Parallel()

	server := vhostServer(t, map[string]string{
		"admin.example.com": "<html><body><h1>Admin console</h1><p>Staff tooling and audit logs live here.</p></body></html>",
		"dev.example.com":   "<html><body><h1>Dev environment</h1><p>Unstable build, expect breakage at any time.</p></body></html>",
	})

	results, stats := runScan(t, server, func(o *Options) {
		o.Wordlist = []string{"admin", "dev", "www", "mail", "ftp"}
		o.Domains = []string{"example.com"}
	})

	var found []string
	for _, r := range results {
		found = append(found, r.Vhost)
	}
	want := []string{"admin.example.com", "dev.example.com"}
	if strings.Join(found, ",") != strings.Join(want, ",") {
		t.Errorf("found %v, want %v", found, want)
	}

	if got := stats.Hits.Load(); got != 2 {
		t.Errorf("Hits = %d, want 2", got)
	}
	if got := stats.Errors.Load(); got != 0 {
		t.Errorf("Errors = %d, want 0", got)
	}

	for _, r := range results {
		if r.Status != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", r.Vhost, r.Status)
		}
		if r.ContentLength <= 0 {
			t.Errorf("%s: ContentLength = %d, want positive", r.Vhost, r.ContentLength)
		}
		if r.Scheme != "http" {
			t.Errorf("%s: scheme = %q, want http", r.Vhost, r.Scheme)
		}
	}
}

func TestEnumerateVhostsAppliesFilters(t *testing.T) {
	t.Parallel()

	server := vhostServer(t, map[string]string{
		"admin.example.com": "<html><body><h1>Admin console</h1><p>Staff tooling and audit logs live here.</p></body></html>",
		"dev.example.com":   "<html><body><h1>Dev environment</h1><p>Unstable build, expect breakage at any time.</p></body></html>",
	})

	tests := []struct {
		name   string
		mutate func(*Options)
		want   []string
	}{
		{
			name:   "regex keeps only the matching body",
			mutate: func(o *Options) { o.MatchRegex = "Admin console" },
			want:   []string{"admin.example.com"},
		},
		{
			name:   "a filtered status removes everything",
			mutate: func(o *Options) { o.FilterStatus = "200" },
			want:   nil,
		},
		{
			name:   "a matched status keeps everything",
			mutate: func(o *Options) { o.MatchStatus = "200" },
			want:   []string{"admin.example.com", "dev.example.com"},
		},
		{
			name:   "a filter beats a match on the same value",
			mutate: func(o *Options) { o.MatchStatus = "200"; o.FilterStatus = "200" },
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			results, _ := runScan(t, server, func(o *Options) {
				o.Wordlist = []string{"admin", "dev", "www"}
				o.Domains = []string{"example.com"}
				tc.mutate(o)
			})

			var found []string
			for _, r := range results {
				found = append(found, r.Vhost)
			}
			if strings.Join(found, ",") != strings.Join(tc.want, ",") {
				t.Errorf("found %v, want %v", found, tc.want)
			}
		})
	}
}

// TestMaxErrorsAbandonsDeadHost checks the error ceiling: a host that never
// answers must not consume the whole wordlist.
func TestMaxErrorsAbandonsDeadHost(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The baseline succeeds so the scan starts; every later request is
		// killed at the connection level.
		if attempts.Add(1) > 2 {
			if hijacker, ok := w.(http.Hijacker); ok {
				conn, _, err := hijacker.Hijack()
				if err == nil {
					conn.Close()
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 not configured</body></html>"))
	}))
	t.Cleanup(server.Close)

	wordlist := make([]string, 400)
	for i := range wordlist {
		wordlist[i] = "host" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}

	_, stats := runScan(t, server, func(o *Options) {
		o.Wordlist = wordlist
		o.Domains = []string{"example.com"}
		o.BaselineSamples = 1
		o.MaxErrors = 5
		o.Retries = 0
		o.Threads = 1
	})

	if stats.DeadHosts.Load() != 1 {
		t.Errorf("DeadHosts = %d, want 1", stats.DeadHosts.Load())
	}
	if got := stats.Requests.Load(); got > 100 {
		t.Errorf("made %d requests against a dead host; the ceiling did not engage", got)
	}
	if stats.Skipped.Load() == 0 {
		t.Error("expected the remaining wordlist to be skipped")
	}
}

// TestResumeSkipsCompletedWork checks that a second run with the same
// checkpoint does not redo finished jobs.
func TestResumeSkipsCompletedWork(t *testing.T) {
	t.Parallel()

	server := vhostServer(t, map[string]string{
		"admin.example.com": "<html><body><h1>Admin console</h1><p>Staff tooling lives here.</p></body></html>",
	})
	checkpoint := filepath.Join(t.TempDir(), "scan.checkpoint")

	wordlist := []string{"admin", "dev", "www", "mail"}
	setup := func(o *Options) {
		o.Wordlist = wordlist
		o.Domains = []string{"example.com"}
		o.Resume = checkpoint
		o.BaselineSamples = 1
	}

	first, firstStats := runScan(t, server, setup)
	if len(first) != 1 {
		t.Fatalf("first run found %d vhosts, want 1", len(first))
	}
	if firstStats.Resumed != 0 {
		t.Errorf("first run Resumed = %d, want 0", firstStats.Resumed)
	}

	second, secondStats := runScan(t, server, setup)
	if secondStats.Resumed != len(wordlist) {
		t.Errorf("second run Resumed = %d, want %d", secondStats.Resumed, len(wordlist))
	}
	if len(second) != 0 {
		t.Errorf("second run re-reported %d vhosts; completed work should be skipped", len(second))
	}
	// Only the baseline probe should have gone out.
	if got := secondStats.Requests.Load(); got > 1 {
		t.Errorf("second run made %d requests, want only the baseline", got)
	}
}

// TestBaselineSamplesRejectDynamicContent is the false-positive guard: a target
// whose page changes on every request must not report every vhost as a find.
func TestBaselineSamplesRejectDynamicContent(t *testing.T) {
	t.Parallel()

	var counter atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A stable page carrying one volatile token, as a CSRF field or a
		// request id would be.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 not configured. request id " +
			strings.Repeat("x", 8) + string(rune('a'+counter.Add(1)%26)) + "</body></html>"))
	}))
	t.Cleanup(server.Close)

	results, _ := runScan(t, server, func(o *Options) {
		o.Wordlist = []string{"admin", "dev", "www", "mail"}
		o.Domains = []string{"example.com"}
		o.BaselineSamples = 3
	})

	if len(results) != 0 {
		t.Errorf("reported %d vhosts against a server with no vhosts at all: %v", len(results), results)
	}
}

func TestEnumerateVhostsRejectsEmptyWordlist(t *testing.T) {
	t.Parallel()

	reporter, err := NewReporter("", "", true, false)
	if err != nil {
		t.Fatalf("new reporter: %v", err)
	}

	opts := testOptions()
	opts.Targets = []Target{{Host: "127.0.0.1", Port: 1, TLS: false}}
	opts.Paths = []string{"/"}

	if _, err := EnumerateVhosts(context.Background(), opts, reporter); err == nil {
		t.Fatal("expected an error for an empty wordlist")
	}
}
