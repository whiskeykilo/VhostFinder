package utils

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxErrors is how many consecutive failures a host is allowed before it
// is abandoned. Without a ceiling, one unresponsive host burns the entire
// wordlist against a connection timeout.
const DefaultMaxErrors = 20

// Stats summarises a run.
type Stats struct {
	Targets   int
	Requests  atomic.Int64
	Hits      atomic.Int64
	Errors    atomic.Int64
	Skipped   atomic.Int64
	Resumed   int
	DeadHosts atomic.Int64
	Duration  time.Duration
}

// Job is one virtual host to try against one target and path.
type Job struct {
	Baseline *Baseline
	Target   Target
	Path     string
	Domain   string
}

// hostState tracks consecutive failures for one target so a dead host can be
// abandoned without stopping the rest of the scan.
type hostState struct {
	consecutive atomic.Int64
	dead        atomic.Bool
}

// PermuteDomains builds the virtual host list. Entries in the wordlist are used
// as-is when no -domain is given, and otherwise treated as subdomain prefixes to
// be combined with each domain.
func PermuteDomains(wordlist []string, domainList []string) []string {
	var domains []string
	seen := make(map[string]struct{}, len(wordlist))

	add := func(d string) {
		d = strings.TrimSpace(strings.TrimSuffix(d, "."))
		if d == "" {
			return
		}
		if _, dup := seen[d]; dup {
			return
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
	}

	for _, guess := range wordlist {
		guess = strings.TrimSpace(guess)
		if guess == "" {
			continue
		}
		if len(domainList) == 0 {
			add(guess)
			continue
		}
		for _, domain := range domainList {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}
			add(guess + "." + domain)
		}
	}

	return domains
}

// baselineSuffix returns the domain shape to give random baseline hosts.
func baselineSuffix(opts *Options, domains []string) string {
	if len(opts.Domains) > 0 {
		return opts.Domains[0]
	}
	if len(domains) > 0 {
		return domains[0]
	}
	return ""
}

// EnumerateVhosts runs a full scan. It returns when every job is finished or ctx
// is cancelled; a cancelled run still returns the stats gathered so far.
func EnumerateVhosts(ctx context.Context, opts *Options, reporter *Reporter) (*Stats, error) {
	started := time.Now()
	stats := &Stats{Targets: len(opts.Targets)}

	domains := PermuteDomains(opts.Wordlist, opts.Domains)
	if len(domains) == 0 {
		return stats, errors.New("the wordlist produced no virtual hosts to try")
	}

	fuzzer, err := NewFuzzer(opts, reporter)
	if err != nil {
		return stats, err
	}
	matcher, err := NewMatcher(opts)
	if err != nil {
		return stats, err
	}
	delay, err := ParseDelay(opts.Delay)
	if err != nil {
		return stats, err
	}
	limiter := NewLimiter(opts.Rate)
	defer limiter.Stop()

	checkpoint, err := OpenCheckpoint(opts.Resume, Fingerprint(opts))
	if err != nil {
		return stats, err
	}
	defer func() {
		if cerr := checkpoint.Close(); cerr != nil {
			reporter.Warn("Could not flush checkpoint: %s", cerr)
		}
	}()
	stats.Resumed = checkpoint.Completed()
	if stats.Resumed > 0 {
		reporter.Info("Resuming: %d jobs already completed", stats.Resumed)
	}

	hosts := make(map[Target]*hostState, len(opts.Targets))
	for _, t := range opts.Targets {
		hosts[t] = &hostState{}
	}

	baselines := acquireBaselines(ctx, fuzzer, opts, domains, reporter, stats)
	if len(baselines) == 0 {
		return stats, errors.New("no usable baseline on any target (use -force to scan anyway)")
	}

	jobs := make(chan Job)
	var wg sync.WaitGroup
	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runWorker(ctx, fuzzer, matcher, limiter, delay, checkpoint, hosts, jobs, stats, reporter)
		}()
	}

producer:
	for _, target := range opts.Targets {
		for _, path := range opts.Paths {
			baseline, ok := baselines[baselineKey{target, path}]
			if !ok {
				continue
			}
			state := hosts[target]
			for _, domain := range domains {
				if ctx.Err() != nil {
					break producer
				}
				if state.dead.Load() {
					stats.Skipped.Add(1)
					continue
				}
				if checkpoint.Done(target, path, domain) {
					continue
				}
				select {
				case jobs <- Job{Baseline: baseline, Target: target, Path: path, Domain: domain}:
				case <-ctx.Done():
					break producer
				}
			}
		}
	}

	close(jobs)
	wg.Wait()

	stats.Duration = time.Since(started)
	return stats, ctx.Err()
}

// baselineKey identifies the baseline for one target and path.
type baselineKey struct {
	target Target
	path   string
}

// acquireBaselines probes every target and path in parallel. Doing this serially
// meant a scan over a large -ips list spent minutes before issuing its first
// real request.
func acquireBaselines(ctx context.Context, fuzzer *Fuzzer, opts *Options, domains []string, reporter *Reporter, stats *Stats) map[baselineKey]*Baseline {
	suffix := baselineSuffix(opts, domains)
	samples := opts.BaselineSamples
	if samples < 1 {
		samples = DefaultBaselineSamples
	}

	var (
		mu     sync.Mutex
		result = make(map[baselineKey]*Baseline)
		wg     sync.WaitGroup
	)

	parallel := opts.Threads
	if parallel < 1 {
		parallel = 1
	}
	sem := make(chan struct{}, parallel)

	for _, target := range opts.Targets {
		for _, path := range opts.Paths {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(target Target, path string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				reporter.Verbosef("Obtaining baseline on: %s", target.URL(path))
				baseline, err := NewBaseline(ctx, fuzzer, target, path, suffix, samples, opts.BaselineRefresh)
				stats.Requests.Add(int64(samples))
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					reporter.Warn("Failed to obtain baseline (%s): %s", target.URL(path), err)
					if !opts.Force {
						return
					}
					reporter.Warn("Forcing scan of %s%s with no baseline: every response will be reported", target, path)
					baseline = ForcedBaseline()
				} else if !baseline.Stable() {
					reporter.Warn("Baseline for %s%s is unstable: the target varies its own responses, so findings here are unreliable", target, path)
				}

				mu.Lock()
				result[baselineKey{target, path}] = baseline
				mu.Unlock()
			}(target, path)
		}
	}

	wg.Wait()
	return result
}

// runWorker consumes jobs until the channel closes or the context is cancelled.
func runWorker(
	ctx context.Context,
	fuzzer *Fuzzer,
	matcher *Matcher,
	limiter *Limiter,
	delay *Delay,
	checkpoint *Checkpoint,
	hosts map[Target]*hostState,
	jobs <-chan Job,
	stats *Stats,
	reporter *Reporter,
) {
	for job := range jobs {
		if ctx.Err() != nil {
			return
		}

		state := hosts[job.Target]
		if state.dead.Load() {
			stats.Skipped.Add(1)
			continue
		}

		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return
			}
		}
		if delay != nil {
			if err := delay.Sleep(ctx); err != nil {
				return
			}
		}

		processJob(ctx, fuzzer, matcher, checkpoint, state, job, stats, reporter)
	}
}

// processJob tries one virtual host and reports the outcome.
func processJob(
	ctx context.Context,
	fuzzer *Fuzzer,
	matcher *Matcher,
	checkpoint *Checkpoint,
	state *hostState,
	job Job,
	stats *Stats,
	reporter *Reporter,
) {
	opts := fuzzer.Options

	differs, score, result, err := fuzzer.TestDomain(ctx, job.Target, job.Domain, job.Path, job.Baseline.Samples(ctx))
	stats.Requests.Add(1)

	if err != nil {
		if ctx.Err() != nil {
			return
		}
		stats.Errors.Add(1)
		reporter.Verbosef("[%s] [%s] %s -> %s", job.Target.Host, job.Path, job.Domain, err)

		if opts.MaxErrors > 0 && state.consecutive.Add(1) >= int64(opts.MaxErrors) {
			if state.dead.CompareAndSwap(false, true) {
				stats.DeadHosts.Add(1)
				reporter.Warn("Abandoning %s after %d consecutive errors", job.Target, opts.MaxErrors)
			}
		}
		return
	}

	state.consecutive.Store(0)

	if err := checkpoint.Record(job.Target, job.Path, job.Domain); err != nil {
		reporter.Warn("Could not record checkpoint: %s", err)
	}

	if !differs {
		reporter.Verbosef("[%s] [%s] [%d] [%d] %s is not different from the baseline (similarity %.2f)",
			job.Target.Host, job.Path, result.Status, result.ContentLength, job.Domain, score)
		return
	}

	if !matcher.Allows(result) {
		reporter.Verbosef("[%s] [%s] [%d] [%d] %s differs but was filtered out",
			job.Target.Host, job.Path, result.Status, result.ContentLength, job.Domain)
		return
	}

	var verified *bool
	if opts.Verify {
		ok := fuzzer.CompareGeneric(ctx, job.Domain, job.Path, result.Response)
		stats.Requests.Add(1)
		if !ok {
			reporter.Verbosef("[%s] [%s] [%d] [%d] %s differs from the baseline but matches the public site",
				job.Target.Host, job.Path, result.Status, result.ContentLength, job.Domain)
			return
		}
		verified = &ok
	}

	stats.Hits.Add(1)
	reporter.Result(Result{
		Timestamp:     time.Now().UTC(),
		Host:          job.Target.Host,
		Port:          job.Target.Port,
		Scheme:        job.Target.Scheme(),
		Path:          job.Path,
		Vhost:         job.Domain,
		Status:        result.Status,
		ContentLength: result.ContentLength,
		Words:         result.Words,
		Lines:         result.Lines,
		Similarity:    score,
		Verified:      verified,
		URL:           job.Target.URL(job.Path),
	})
}

// Summary renders the end-of-run counters.
func (s *Stats) Summary() string {
	return fmt.Sprintf(
		"Done in %s: %d targets, %d requests, %d vhosts found, %d errors, %d skipped, %d hosts abandoned",
		s.Duration.Round(time.Millisecond),
		s.Targets,
		s.Requests.Load(),
		s.Hits.Load(),
		s.Errors.Load(),
		s.Skipped.Load(),
		s.DeadHosts.Load(),
	)
}
