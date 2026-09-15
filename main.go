// Command VhostFinder discovers virtual hosts by fuzzing the HTTP Host header
// against a target and comparing each response to a baseline.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/projectdiscovery/goflags"
	"github.com/whiskeykilo/VhostFinder/utils"
)

// Build information, injected at release time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type options struct {
	baselineRefresh int
	baselineSamples int
	delay           string
	domains         goflags.StringSlice
	filterLines     string
	filterRegex     string
	filterSize      string
	filterStatus    string
	filterWords     string
	force           bool
	headers         goflags.StringSlice
	ip              goflags.StringSlice
	ips             goflags.StringSlice
	matchLines      string
	matchRegex      string
	matchSize       string
	matchStatus     string
	matchWords      string
	maxBody         int
	maxErrors       int
	maxTargets      int
	output          string
	outputFormat    string
	path            goflags.StringSlice
	paths           goflags.StringSlice
	port            int
	proxy           string
	rate            int
	resume          string
	retries         int
	showVersion     bool
	silent          bool
	sni             string
	threads         int
	threshold       string
	timeout         int
	tls             bool
	verbose         bool
	verify          bool
	wordlist        goflags.StringSlice
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	opt, flagSet, err := parseFlags()
	if err != nil {
		return err
	}

	if opt.showVersion {
		fmt.Printf("VhostFinder %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}

	targets, err := collectTargets(opt)
	if err != nil {
		return err
	}
	if len(targets) == 0 || len(opt.wordlist) == 0 {
		flagSet.CommandLine.Usage()
		fmt.Fprintln(os.Stderr)
		return errors.New("set at least one target with -ip, -ips or on stdin, and a wordlist with -wordlist")
	}

	opts, err := buildOptions(opt, targets)
	if err != nil {
		return err
	}

	reporter, err := utils.NewReporter(opts.Output, opts.OutputFormat, opts.Silent, opts.Verbose)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := reporter.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "[!] Could not close output file: %s\n", cerr)
		}
	}()

	// A scan is interruptible: Ctrl-C stops dispatching, lets in-flight requests
	// unwind, and still flushes the checkpoint and prints the summary.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reporter.Info("Finding vhosts across %d target(s) and %d path(s)", len(opts.Targets), len(opts.Paths))
	if opts.SNI == utils.SNINone && opts.Tls {
		reporter.Warn("-sni none sends no TLS server name; SNI-routed targets will under-report")
	}

	stats, err := utils.EnumerateVhosts(ctx, opts, reporter)
	if stats != nil {
		reporter.Info("%s", stats.Summary())
	}

	if errors.Is(err, context.Canceled) {
		reporter.Warn("Interrupted")
		return nil
	}
	return err
}

func parseFlags() (*options, *goflags.FlagSet, error) {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("VhostFinder discovers virtual hosts by fuzzing the HTTP Host header.")
	opt := &options{}

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVar(&opt.ip, "ip", nil, "Target to fuzz: IP, hostname, CIDR, host:port or URL", goflags.StringSliceOptions),
		flagSet.StringSliceVar(&opt.ips, "ips", nil, "File of targets, one per line (also read from stdin when piped)", goflags.FileStringSliceOptions),
		flagSet.StringSliceVar(&opt.wordlist, "wordlist", nil, "File of FQDNs or subdomain prefixes to fuzz for", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&opt.domains, "domain", "d", nil, "Domain(s) to append to a subdomain wordlist (Ex: example1.com)", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&opt.path, "path", "p", nil, "Custom path(s) to send during fuzzing", goflags.StringSliceOptions),
		flagSet.StringSliceVar(&opt.paths, "paths", nil, "File list of custom paths", goflags.FileStringSliceOptions),
	)

	flagSet.CreateGroup("request", "Request",
		flagSet.IntVar(&opt.port, "port", 443, "Default port, when a target does not carry one"),
		flagSet.BoolVar(&opt.tls, "tls", true, "Use TLS (disable with -tls=false)"),
		flagSet.StringVar(&opt.sni, "sni", utils.SNIAuto, "TLS server name: \"auto\" follows the fuzzed vhost, \"none\" sends none, or a literal name"),
		flagSet.StringSliceVarP(&opt.headers, "header", "H", nil, "Custom header(s) for each request", goflags.StringSliceOptions),
		flagSet.StringVar(&opt.proxy, "proxy", "", "Proxy (Ex: http://127.0.0.1:8080)"),
		flagSet.IntVar(&opt.timeout, "timeout", 8, "Timeout per HTTP request, in seconds"),
		flagSet.IntVar(&opt.retries, "retries", 1, "Retries for transient network errors"),
		flagSet.IntVar(&opt.maxBody, "max-body", int(utils.DefaultMaxBody), "Maximum response body bytes to read"),
	)

	flagSet.CreateGroup("detection", "Detection",
		flagSet.StringVar(&opt.threshold, "threshold", strconv.FormatFloat(utils.DefaultThreshold, 'f', -1, 64), "Similarity below which a response counts as different (0.0-1.0)"),
		flagSet.IntVar(&opt.baselineSamples, "baseline-samples", utils.DefaultBaselineSamples, "Baseline probes per target and path"),
		flagSet.IntVar(&opt.baselineRefresh, "baseline-refresh", 0, "Re-probe the baseline every N requests (0 disables)"),
		flagSet.BoolVar(&opt.force, "force", false, "Scan even when the baseline fails, reporting every response"),
		flagSet.BoolVar(&opt.verify, "verify", false, "Verify a vhost differs from the publicly resolved site"),
	)

	flagSet.CreateGroup("matchers", "Matchers and filters",
		flagSet.StringVar(&opt.matchStatus, "mc", "", "Match status codes (Ex: 200,301-399)"),
		flagSet.StringVar(&opt.filterStatus, "fc", "", "Filter out status codes"),
		flagSet.StringVar(&opt.matchSize, "ms", "", "Match response sizes"),
		flagSet.StringVar(&opt.filterSize, "fs", "", "Filter out response sizes"),
		flagSet.StringVar(&opt.matchWords, "mw", "", "Match response word counts"),
		flagSet.StringVar(&opt.filterWords, "fw", "", "Filter out response word counts"),
		flagSet.StringVar(&opt.matchLines, "ml", "", "Match response line counts"),
		flagSet.StringVar(&opt.filterLines, "fl", "", "Filter out response line counts"),
		flagSet.StringVar(&opt.matchRegex, "mr", "", "Match responses whose body matches this regex"),
		flagSet.StringVar(&opt.filterRegex, "fr", "", "Filter out responses whose body matches this regex"),
	)

	flagSet.CreateGroup("pacing", "Pacing",
		flagSet.IntVarP(&opt.threads, "threads", "t", 10, "Number of concurrent workers"),
		flagSet.IntVar(&opt.rate, "rate", 0, "Maximum requests per second (0 is unlimited)"),
		flagSet.StringVar(&opt.delay, "delay", "", "Delay before each request in seconds, fixed or a range (Ex: 0.1-2.0)"),
		flagSet.IntVar(&opt.maxErrors, "max-errors", utils.DefaultMaxErrors, "Abandon a host after N consecutive errors (0 disables)"),
		flagSet.IntVar(&opt.maxTargets, "max-targets", utils.DefaultMaxTargets, "Maximum targets after CIDR expansion"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opt.output, "output", "o", "", "Write results to a file"),
		flagSet.StringVar(&opt.outputFormat, "of", utils.FormatText, "Output file format: txt, json, jsonl or csv"),
		flagSet.BoolVar(&opt.silent, "silent", false, "Print only discovered vhosts on stdout"),
		flagSet.BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose mode"),
		flagSet.StringVar(&opt.resume, "resume", "", "Checkpoint file to resume from and append to"),
		flagSet.BoolVar(&opt.showVersion, "version", false, "Show version and exit"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, nil, fmt.Errorf("could not parse flags: %w", err)
	}

	return opt, flagSet, nil
}

// collectTargets gathers target specifications from flags and, when stdin is a
// pipe, from stdin as well.
func collectTargets(opt *options) ([]string, error) {
	var specs []string
	specs = append(specs, opt.ips...)
	specs = append(specs, opt.ip...)

	// Stdin is only consulted when no target was named explicitly. Reading a
	// pipe that nobody closes blocks forever, so a run that already knows its
	// targets must never touch it.
	if len(specs) == 0 {
		piped, err := readPipedStdin()
		if err != nil {
			return nil, err
		}
		specs = append(specs, piped...)
	}

	var cleaned []string
	for _, s := range specs {
		if s = strings.TrimSpace(s); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	return cleaned, nil
}

// readPipedStdin reads targets from stdin when it is not a terminal, so that
// VhostFinder composes with subfinder, httpx and friends.
func readPipedStdin() ([]string, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return nil, nil
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return nil, nil
	}
	lines, err := utils.ReadLines(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("could not read targets from stdin: %w", err)
	}
	return lines, nil
}

func buildOptions(opt *options, targetSpecs []string) (*utils.Options, error) {
	threshold, err := strconv.ParseFloat(strings.TrimSpace(opt.threshold), 64)
	if err != nil {
		return nil, fmt.Errorf("invalid -threshold %q: %w", opt.threshold, err)
	}
	if threshold < 0 || threshold > 1 {
		return nil, fmt.Errorf("-threshold must be between 0.0 and 1.0, got %v", threshold)
	}

	if opt.threads < 1 {
		return nil, errors.New("-threads must be at least 1")
	}
	if opt.timeout < 1 {
		return nil, errors.New("-timeout must be at least 1 second")
	}
	if opt.retries < 0 {
		return nil, errors.New("-retries cannot be negative")
	}
	if opt.maxBody < 1 {
		return nil, errors.New("-max-body must be at least 1")
	}
	if opt.baselineSamples < 1 {
		return nil, errors.New("-baseline-samples must be at least 1")
	}
	if opt.output != "" && !utils.ValidFormat(opt.outputFormat) {
		return nil, fmt.Errorf("unknown -of %q (want one of %v)", opt.outputFormat, utils.OutputFormats)
	}

	sni := strings.TrimSpace(opt.sni)
	if sni == "" {
		sni = utils.SNIAuto
	}

	targets, err := utils.ParseTargets(targetSpecs, opt.port, opt.tls, opt.maxTargets)
	if err != nil {
		return nil, err
	}

	paths := normalisePaths(append(append([]string{}, opt.paths...), opt.path...))

	return &utils.Options{
		Targets:  targets,
		Wordlist: opt.wordlist,
		Domains:  opt.domains,
		Paths:    paths,

		Port:    opt.port,
		Tls:     opt.tls,
		Proxy:   opt.proxy,
		Headers: opt.headers,
		Timeout: opt.timeout,
		MaxBody: int64(opt.maxBody),
		SNI:     sni,
		Retries: opt.retries,

		Threshold:       threshold,
		BaselineSamples: opt.baselineSamples,
		BaselineRefresh: opt.baselineRefresh,
		Force:           opt.force,
		Verify:          opt.verify,

		Threads:   opt.threads,
		Rate:      opt.rate,
		Delay:     opt.delay,
		MaxErrors: opt.maxErrors,

		MatchStatus:  opt.matchStatus,
		FilterStatus: opt.filterStatus,
		MatchSize:    opt.matchSize,
		FilterSize:   opt.filterSize,
		MatchWords:   opt.matchWords,
		FilterWords:  opt.filterWords,
		MatchLines:   opt.matchLines,
		FilterLines:  opt.filterLines,
		MatchRegex:   opt.matchRegex,
		FilterRegex:  opt.filterRegex,

		Output:       opt.output,
		OutputFormat: opt.outputFormat,
		Silent:       opt.silent,
		Verbose:      opt.verbose,
		Resume:       opt.resume,
	}, nil
}

// normalisePaths ensures every path starts with a slash and defaults to "/".
func normalisePaths(raw []string) []string {
	var paths []string
	seen := make(map[string]struct{})
	for _, path := range raw {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		paths = []string{"/"}
	}
	return paths
}
