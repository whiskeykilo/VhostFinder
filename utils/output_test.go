package utils

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func outBoolPtr(b bool) *bool { return &b }

// outSampleResults returns two representative Result values: the first
// with Verified set true, the second with Verified left nil - covering both
// branches of the CSV "verified" column and giving every writer format
// something non-trivial to round-trip.
func outSampleResults() (Result, Result) {
	ts := time.Date(2026, 9, 15, 10, 30, 0, 0, time.UTC)
	r1 := Result{
		Timestamp:     ts,
		Host:          "10.0.0.5",
		Port:          443,
		Scheme:        "https",
		Path:          "/",
		Vhost:         "admin.example.com",
		Status:        200,
		ContentLength: 1024,
		Words:         120,
		Lines:         40,
		Similarity:    0.12,
		Verified:      outBoolPtr(true),
		URL:           "https://10.0.0.5/",
	}
	r2 := Result{
		Timestamp:     ts.Add(5 * time.Second),
		Host:          "10.0.0.5",
		Port:          443,
		Scheme:        "https",
		Path:          "/login",
		Vhost:         "portal.example.com",
		Status:        302,
		ContentLength: 0,
		Words:         0,
		Lines:         0,
		Similarity:    0.03,
		Verified:      nil,
		URL:           "https://10.0.0.5/login",
	}
	return r1, r2
}

func TestValidFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{FormatText, true},
		{FormatJSON, true},
		{FormatJSONL, true},
		{FormatCSV, true},
		{"xml", false},
		{"yaml", false},
		{"", false},
		{"JSON", false}, // case sensitive
		{"csv ", false}, // no trimming
	}

	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("%q", tt.name), func(t *testing.T) {
			t.Parallel()
			if got := ValidFormat(tt.name); got != tt.want {
				t.Errorf("ValidFormat(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestNewReporterBadFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "out.bogus")

	r, err := NewReporter(path, "bogus-format", false, false)
	if err == nil {
		t.Fatal("NewReporter with an invalid format: want error, got nil")
	}
	if r != nil {
		t.Errorf("NewReporter with an invalid format: want nil reporter, got %+v", r)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("NewReporter with an invalid format created a file at %s", path)
	}
}

func TestNewReporterEmptyPathNeverCreatesFile(t *testing.T) {
	t.Parallel()

	r, err := NewReporter("", FormatJSON, false, false)
	if err != nil {
		t.Fatalf("NewReporter(\"\", ...) error = %v, want nil", err)
	}
	if r == nil {
		t.Fatal("NewReporter(\"\", ...) = nil, want a usable reporter")
	}
	if r.file != nil {
		t.Errorf("NewReporter(\"\", ...) set up a file writer: %+v", r.file)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close() on a path-less reporter error = %v, want nil", err)
	}
}

func TestReporterWriterRoundTrip(t *testing.T) {
	t.Parallel()

	r1, r2 := outSampleResults()

	t.Run(FormatJSON, func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "out.json")

		rep, err := NewReporter(path, FormatJSON, true, false)
		if err != nil {
			t.Fatalf("NewReporter error = %v", err)
		}
		rep.Result(r1)
		rep.Result(r2)

		if err := rep.Close(); err != nil {
			t.Fatalf("Close error = %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile error = %v", err)
		}

		var got []Result
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("output is not a JSON array of objects: %v\ndata: %s", err, data)
		}
		if len(got) != 2 {
			t.Fatalf("got %d results, want 2", len(got))
		}
		if got[0].Vhost != r1.Vhost || got[0].Status != r1.Status {
			t.Errorf("result[0] = {Vhost:%q Status:%d}, want {Vhost:%q Status:%d}", got[0].Vhost, got[0].Status, r1.Vhost, r1.Status)
		}
		if got[1].Vhost != r2.Vhost || got[1].Status != r2.Status {
			t.Errorf("result[1] = {Vhost:%q Status:%d}, want {Vhost:%q Status:%d}", got[1].Vhost, got[1].Status, r2.Vhost, r2.Status)
		}
	})

	t.Run(FormatJSONL, func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "out.jsonl")

		rep, err := NewReporter(path, FormatJSONL, true, false)
		if err != nil {
			t.Fatalf("NewReporter error = %v", err)
		}
		rep.Result(r1)
		rep.Result(r2)
		if err := rep.Close(); err != nil {
			t.Fatalf("Close error = %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile error = %v", err)
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("got %d lines, want 2: %q", len(lines), lines)
		}
		want := []Result{r1, r2}
		for i, line := range lines {
			var got Result
			if err := json.Unmarshal([]byte(line), &got); err != nil {
				t.Fatalf("line %d is not a single JSON object: %v\nline: %s", i, err, line)
			}
			if got.Vhost != want[i].Vhost || got.Status != want[i].Status {
				t.Errorf("line %d = {Vhost:%q Status:%d}, want {Vhost:%q Status:%d}", i, got.Vhost, got.Status, want[i].Vhost, want[i].Status)
			}
		}
	})

	t.Run(FormatCSV, func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "out.csv")

		rep, err := NewReporter(path, FormatCSV, true, false)
		if err != nil {
			t.Fatalf("NewReporter error = %v", err)
		}
		rep.Result(r1)
		rep.Result(r2)
		if err := rep.Close(); err != nil {
			t.Fatalf("Close error = %v", err)
		}

		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("Open error = %v", err)
		}
		defer f.Close()

		records, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatalf("csv parse error = %v", err)
		}
		if len(records) != 3 {
			t.Fatalf("got %d CSV records (incl. header), want 3", len(records))
		}

		wantHeader := []string{"timestamp", "host", "port", "scheme", "path", "vhost",
			"status", "content_length", "words", "lines", "similarity", "verified", "url"}
		if len(records[0]) != len(wantHeader) {
			t.Fatalf("header has %d columns, want %d: %v", len(records[0]), len(wantHeader), records[0])
		}
		for i, col := range wantHeader {
			if records[0][i] != col {
				t.Errorf("header[%d] = %q, want %q", i, records[0][i], col)
			}
		}

		const verifiedCol = 11
		if got, want := records[1][verifiedCol], "true"; got != want {
			t.Errorf("row 1 verified column = %q, want %q (Verified == true)", got, want)
		}
		if got, want := records[2][verifiedCol], ""; got != want {
			t.Errorf("row 2 verified column = %q, want %q (Verified == nil)", got, want)
		}

		const vhostCol = 5
		if got, want := records[1][vhostCol], r1.Vhost; got != want {
			t.Errorf("row 1 vhost column = %q, want %q", got, want)
		}
		if got, want := records[2][vhostCol], r2.Vhost; got != want {
			t.Errorf("row 2 vhost column = %q, want %q", got, want)
		}

		const statusCol = 6
		if got, want := records[1][statusCol], strconv.Itoa(r1.Status); got != want {
			t.Errorf("row 1 status column = %q, want %q", got, want)
		}
	})

	t.Run(FormatText, func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "out.txt")

		rep, err := NewReporter(path, FormatText, true, false)
		if err != nil {
			t.Fatalf("NewReporter error = %v", err)
		}
		rep.Result(r1)
		rep.Result(r2)
		if err := rep.Close(); err != nil {
			t.Fatalf("Close error = %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile error = %v", err)
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("got %d lines, want 2: %q", len(lines), lines)
		}
		want := []Result{r1, r2}
		for i, res := range want {
			wantLine := fmt.Sprintf("[%s] [%s] [%d] [%d] %s", res.Host, res.Path, res.Status, res.ContentLength, res.Vhost)
			if lines[i] != wantLine {
				t.Errorf("line %d = %q, want %q", i, lines[i], wantLine)
			}
		}
	})
}

func TestJSONReporterBuffersUntilClose(t *testing.T) {
	t.Parallel()

	r1, r2 := outSampleResults()
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	rep, err := NewReporter(path, FormatJSON, true, false)
	if err != nil {
		t.Fatalf("NewReporter error = %v", err)
	}
	rep.Result(r1)
	rep.Result(r2)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile before Close error = %v", err)
	}
	if len(before) != 0 {
		t.Errorf("json output has %d bytes before Close, want 0 (buffered): %q", len(before), before)
	}

	if err := rep.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after Close error = %v", err)
	}
	var got []Result
	if err := json.Unmarshal(after, &got); err != nil {
		t.Fatalf("after Close, output is not a JSON array: %v\ndata: %s", err, after)
	}
	if len(got) != 2 {
		t.Errorf("after Close, got %d results, want 2", len(got))
	}
}

func TestReporterConcurrentUse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")

	rep, err := NewReporter(path, FormatJSONL, true, true)
	if err != nil {
		t.Fatalf("NewReporter error = %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rep.Result(Result{
				Host:   "10.0.0.1",
				Path:   "/",
				Vhost:  fmt.Sprintf("host%d.example.com", i),
				Status: 200,
			})
			rep.Info("probing %d", i)
			rep.Warn("retry %d", i)
			rep.Verbosef("detail %d", i)
		}(i)
	}
	wg.Wait()

	if err := rep.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("got %d result lines, want %d (a race would drop or corrupt lines)", len(lines), n)
	}

	seen := make(map[string]bool, n)
	for _, line := range lines {
		var got Result
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("corrupted line: %v\nline: %s", err, line)
		}
		seen[got.Vhost] = true
	}
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("host%d.example.com", i)
		if !seen[want] {
			t.Errorf("missing result for %s", want)
		}
	}
}
