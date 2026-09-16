package utils

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// Output formats accepted by -of.
const (
	FormatText  = "txt"
	FormatJSON  = "json"
	FormatJSONL = "jsonl"
	FormatCSV   = "csv"
)

// OutputFormats lists the valid -of values.
var OutputFormats = []string{FormatText, FormatJSON, FormatJSONL, FormatCSV}

// ValidFormat reports whether name is a supported output format.
func ValidFormat(name string) bool {
	for _, f := range OutputFormats {
		if f == name {
			return true
		}
	}
	return false
}

// Result is one confirmed virtual host.
type Result struct {
	Timestamp     time.Time `json:"timestamp"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	Scheme        string    `json:"scheme"`
	Path          string    `json:"path"`
	Vhost         string    `json:"vhost"`
	Status        int       `json:"status"`
	ContentLength int64     `json:"content_length"`
	Words         int       `json:"words"`
	Lines         int       `json:"lines"`
	Similarity    float64   `json:"similarity"`
	Verified      *bool     `json:"verified,omitempty"`
	URL           string    `json:"url"`
}

// Writer serialises results in one format to one destination.
type Writer interface {
	Write(Result) error
	Close() error
}

// Reporter fans a result out to the console and, when -o is set, to a file.
// Every console line in the program goes through here, which is what keeps
// output from interleaving across workers.
type Reporter struct {
	mu      sync.Mutex
	stdout  io.Writer
	stderr  io.Writer
	file    Writer
	silent  bool
	verbose bool
}

// NewReporter builds a reporter. When path is empty no file is written; the
// returned reporter must be closed to flush buffered formats.
func NewReporter(path, format string, silent, verbose bool) (*Reporter, error) {
	r := &Reporter{
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		silent:  silent,
		verbose: verbose,
	}

	if path == "" {
		return r, nil
	}
	if !ValidFormat(format) {
		return nil, fmt.Errorf("unknown output format %q (want one of %v)", format, OutputFormats)
	}

	// The path comes from -o: pointing this tool at a file of your choosing
	// is the flag working as intended.
	f, err := os.Create(path) //nolint:gosec // G304: operator-supplied output path
	if err != nil {
		return nil, fmt.Errorf("could not open output file: %w", err)
	}

	switch format {
	case FormatJSON:
		r.file = newJSONWriter(f)
	case FormatJSONL:
		r.file = newJSONLWriter(f)
	case FormatCSV:
		r.file = newCSVWriter(f)
	default:
		r.file = newTextWriter(f)
	}

	return r, nil
}

// Result records a finding: a human-readable line on stdout and, if configured,
// a structured record in the output file. Findings are the only thing that ever
// reaches stdout, so the stream can be piped straight into another tool.
func (r *Reporter) Result(res Result) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.silent {
		_, _ = fmt.Fprintf(r.stdout, "[+] [%s] [%s] [%d] [%d] %s\n",
			res.Host, res.Path, res.Status, res.ContentLength, res.Vhost)
	} else {
		_, _ = fmt.Fprintln(r.stdout, res.Vhost)
	}

	if r.file != nil {
		if err := r.file.Write(res); err != nil {
			_, _ = fmt.Fprintf(r.stderr, "[!] Could not write result: %s\n", err)
		}
	}
}

// Info writes an operational message to stderr. Diagnostics never touch stdout.
func (r *Reporter) Info(format string, args ...any) {
	if r.silent {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = fmt.Fprintf(r.stderr, "[!] "+format+"\n", args...)
}

// Verbosef writes a message to stderr only in verbose mode.
func (r *Reporter) Verbosef(format string, args ...any) {
	if !r.verbose || r.silent {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = fmt.Fprintf(r.stderr, "[-] "+format+"\n", args...)
}

// Warn writes a warning to stderr. Warnings are shown even in silent mode,
// because a silent run that is quietly failing is worse than a noisy one.
func (r *Reporter) Warn(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = fmt.Fprintf(r.stderr, "[!] "+format+"\n", args...)
}

// Close flushes and closes the output file.
func (r *Reporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	return r.file.Close()
}

type textWriter struct {
	f *os.File
}

func newTextWriter(f *os.File) Writer { return &textWriter{f: f} }

func (w *textWriter) Write(r Result) error {
	_, err := fmt.Fprintf(w.f, "[%s] [%s] [%d] [%d] %s\n", r.Host, r.Path, r.Status, r.ContentLength, r.Vhost)
	return err
}

func (w *textWriter) Close() error { return w.f.Close() }

type jsonlWriter struct {
	f   *os.File
	enc *json.Encoder
}

func newJSONLWriter(f *os.File) Writer {
	return &jsonlWriter{f: f, enc: json.NewEncoder(f)}
}

func (w *jsonlWriter) Write(r Result) error { return w.enc.Encode(r) }

func (w *jsonlWriter) Close() error { return w.f.Close() }

// jsonWriter buffers results so the file is a single valid JSON array. That
// costs memory proportional to the number of findings, which is small; use
// jsonl for streaming.
type jsonWriter struct {
	f       *os.File
	results []Result
}

func newJSONWriter(f *os.File) Writer {
	return &jsonWriter{f: f, results: []Result{}}
}

func (w *jsonWriter) Write(r Result) error {
	w.results = append(w.results, r)
	return nil
}

func (w *jsonWriter) Close() error {
	enc := json.NewEncoder(w.f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(w.results); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}

type csvWriter struct {
	f *os.File
	w *csv.Writer
}

func newCSVWriter(f *os.File) Writer {
	w := csv.NewWriter(f)
	// Best effort: a header write failure surfaces again on the first record.
	_ = w.Write([]string{"timestamp", "host", "port", "scheme", "path", "vhost",
		"status", "content_length", "words", "lines", "similarity", "verified", "url"})
	return &csvWriter{f: f, w: w}
}

func (w *csvWriter) Write(r Result) error {
	verified := ""
	if r.Verified != nil {
		verified = strconv.FormatBool(*r.Verified)
	}
	return w.w.Write([]string{
		r.Timestamp.Format(time.RFC3339),
		r.Host,
		strconv.Itoa(r.Port),
		r.Scheme,
		r.Path,
		r.Vhost,
		strconv.Itoa(r.Status),
		strconv.FormatInt(r.ContentLength, 10),
		strconv.Itoa(r.Words),
		strconv.Itoa(r.Lines),
		strconv.FormatFloat(r.Similarity, 'f', 4, 64),
		verified,
		r.URL,
	})
}

func (w *csvWriter) Close() error {
	w.w.Flush()
	if err := w.w.Error(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}
