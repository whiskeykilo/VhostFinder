package utils

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// Limiter caps how many requests leave the process per second across all
// workers. A nil Limiter is unlimited.
type Limiter struct {
	ticker *time.Ticker
}

// NewLimiter returns a limiter for the given requests-per-second, or nil when
// rate is zero or negative.
func NewLimiter(rate int) *Limiter {
	if rate <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return &Limiter{ticker: time.NewTicker(interval)}
}

// Wait blocks until the next request is allowed, or until ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.ticker.C:
		return nil
	}
}

// Stop releases the limiter's ticker.
func (l *Limiter) Stop() {
	if l != nil {
		l.ticker.Stop()
	}
}

// Delay is a fixed or randomised pause taken before each request. Jitter makes
// traffic less obviously automated and gives rate-limited targets room to
// breathe.
type Delay struct {
	min, max time.Duration
}

// ParseDelay accepts "0.5" for a fixed delay in seconds or "0.1-2.0" for a
// random delay drawn from that range. An empty spec yields nil.
func ParseDelay(spec string) (*Delay, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	lo, hi, isRange := strings.Cut(spec, "-")
	min, err := parseSeconds(lo)
	if err != nil {
		return nil, fmt.Errorf("invalid delay %q: %w", spec, err)
	}
	max := min
	if isRange {
		max, err = parseSeconds(hi)
		if err != nil {
			return nil, fmt.Errorf("invalid delay %q: %w", spec, err)
		}
	}
	if max < min {
		return nil, fmt.Errorf("delay range %q is inverted", spec)
	}
	if min == 0 && max == 0 {
		return nil, nil
	}
	return &Delay{min: min, max: max}, nil
}

func parseSeconds(s string) (time.Duration, error) {
	seconds, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	if seconds < 0 {
		return 0, fmt.Errorf("delay cannot be negative")
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

// Duration returns the next delay to apply.
func (d *Delay) Duration() time.Duration {
	if d == nil {
		return 0
	}
	if d.max <= d.min {
		return d.min
	}
	return d.min + rand.N(d.max-d.min)
}

// Sleep pauses for the next delay, returning early if ctx is cancelled.
func (d *Delay) Sleep(ctx context.Context) error {
	wait := d.Duration()
	if wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
