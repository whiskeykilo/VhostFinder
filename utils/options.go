package utils

import "fmt"

// Options is the full configuration for a run. It is populated by main from the
// command line and treated as read-only once EnumerateVhosts starts.
type Options struct {
	// Targets and wordlist
	Targets  []Target
	Wordlist []string
	Domains  []string
	Paths    []string

	// Request construction
	Port    int
	Tls     bool
	Proxy   string
	Headers []string
	Timeout int
	MaxBody int64
	SNI     string
	Retries int

	// Detection
	Threshold       float64
	BaselineSamples int
	BaselineRefresh int
	Force           bool
	Verify          bool

	// Pacing and resilience
	Threads   int
	Rate      int
	Delay     string
	MaxErrors int

	// Match and filter conditions
	MatchStatus  string
	FilterStatus string
	MatchSize    string
	FilterSize   string
	MatchWords   string
	FilterWords  string
	MatchLines   string
	FilterLines  string
	MatchRegex   string
	FilterRegex  string

	// Output
	Output       string
	OutputFormat string
	Silent       bool
	Verbose      bool
	Resume       string
}

// Validate checks the option combinations that would otherwise only fail once
// the scan is already under way. Bad flags should be rejected before the first
// request, not after a banner and an empty summary.
func (o *Options) Validate() error {
	if _, err := ParseHeaders(o.Headers); err != nil {
		return err
	}
	if _, err := NewMatcher(o); err != nil {
		return err
	}
	if _, err := ParseDelay(o.Delay); err != nil {
		return err
	}
	if o.Output != "" && !ValidFormat(o.OutputFormat) {
		return fmt.Errorf("unknown output format %q (want one of %v)", o.OutputFormat, OutputFormats)
	}
	return nil
}
