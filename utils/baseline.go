package utils

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// DefaultBaselineSamples is how many baseline probes are taken per target and
// path. One sample cannot tell a real virtual host apart from a page that
// simply varies -- a timestamp, a CSRF token, a rotating backend -- so a
// candidate has to differ from several independent probes to count.
const DefaultBaselineSamples = 3

// Baseline holds the reference responses for one target and path, and refreshes
// them periodically so a long scan does not keep comparing against a snapshot
// the target has since moved away from.
type Baseline struct {
	fuzzer *Fuzzer
	target Target
	path   string
	suffix string

	mu       sync.RWMutex
	samples  []string
	sinceGet int
	refresh  int
	stable   bool
}

// randomHost returns a virtual host that should not exist. A bare UUID is often
// rejected as a malformed name, so it is given the shape of a real hostname by
// borrowing the suffix of the first domain being fuzzed.
func randomHost(suffix string) string {
	if suffix == "" {
		return uuid.NewString()
	}
	return uuid.NewString() + "." + suffix
}

// NewBaseline probes a target and path and returns its reference responses.
func NewBaseline(ctx context.Context, f *Fuzzer, target Target, path, suffix string, samples, refresh int) (*Baseline, error) {
	if samples < 1 {
		samples = 1
	}

	b := &Baseline{
		fuzzer:  f,
		target:  target,
		path:    path,
		suffix:  suffix,
		refresh: refresh,
	}

	if err := b.sample(ctx, samples); err != nil {
		return nil, err
	}
	return b, nil
}

// ForcedBaseline returns a baseline that matches nothing, so every response is
// reported. It backs -force, for targets that refuse the baseline probe itself.
func ForcedBaseline() *Baseline {
	return &Baseline{samples: []string{""}, stable: true}
}

// sample refreshes the reference responses.
func (b *Baseline) sample(ctx context.Context, count int) error {
	fresh := make([]string, 0, count)
	for i := 0; i < count; i++ {
		result, err := b.fuzzer.FuzzHost(ctx, b.target, randomHost(b.suffix), b.path)
		if err != nil {
			if len(fresh) > 0 {
				break // keep what we have; a partial baseline still discriminates
			}
			return err
		}
		fresh = append(fresh, result.Response)
	}
	if len(fresh) == 0 {
		return fmt.Errorf("no baseline samples collected")
	}

	stable := b.fuzzer.sim.Stable(fresh)

	b.mu.Lock()
	b.samples = fresh
	b.sinceGet = 0
	b.stable = stable
	b.mu.Unlock()

	return nil
}

// Stable reports whether the baseline probes agreed with each other. An unstable
// baseline means the target varies its own responses, and findings against it
// carry a high false-positive rate.
func (b *Baseline) Stable() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.stable
}

// Samples returns the current reference responses, re-probing first if the
// refresh interval has elapsed.
func (b *Baseline) Samples(ctx context.Context) []string {
	b.mu.Lock()
	if b.refresh <= 0 || b.fuzzer == nil {
		samples := b.samples
		b.mu.Unlock()
		return samples
	}

	b.sinceGet++
	due := b.sinceGet >= b.refresh
	count := len(b.samples)
	samples := b.samples
	if due {
		// Reset the counter under the same lock so only one caller re-probes.
		b.sinceGet = 0
	}
	b.mu.Unlock()

	if due {
		if err := b.sample(ctx, count); err != nil {
			b.fuzzer.Reporter.Verbosef("Could not refresh baseline for %s%s: %s", b.target, b.path, err)
			return samples
		}
		b.mu.RLock()
		samples = b.samples
		b.mu.RUnlock()
	}

	return samples
}
