package utils

import (
	"context"
	"testing"
	"time"
)

func TestNewLimiterNonPositiveRateReturnsNil(t *testing.T) {
	t.Parallel()

	if l := NewLimiter(0); l != nil {
		t.Errorf("NewLimiter(0) = %+v, want nil", l)
	}
	if l := NewLimiter(-1); l != nil {
		t.Errorf("NewLimiter(-1) = %+v, want nil", l)
	}
}

func TestNilLimiterWaitAndStop(t *testing.T) {
	t.Parallel()

	var l *Limiter

	// Stop must not panic on a nil Limiter.
	l.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); err != ctx.Err() {
		t.Errorf("nil Limiter.Wait(cancelled ctx) = %v, want %v", err, ctx.Err())
	}

	// Even with a live context, a nil Limiter's Wait returns ctx.Err(),
	// which is nil for a context that isn't done.
	live := context.Background()
	if err := l.Wait(live); err != nil {
		t.Errorf("nil Limiter.Wait(live ctx) = %v, want nil", err)
	}
}

func TestLimiterPermitsRateAndTakesFloor(t *testing.T) {
	t.Parallel()

	// 1000 req/s means each Wait is gated roughly 1ms apart. Ask for a
	// handful of waits and assert only a loose lower bound: CI can be
	// slow, so we never assert an upper bound, only that some real pacing
	// happened.
	l := NewLimiter(1000)
	if l == nil {
		t.Fatal("NewLimiter(1000) = nil, want non-nil")
	}
	defer l.Stop()

	ctx := context.Background()
	const n = 5
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait(%d) unexpected error: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	// Expected floor for n waits at 1000/s is roughly (n-1)*1ms since the
	// first tick can fire almost immediately. Use a very generous lower
	// bound tolerance to avoid flakiness.
	const floor = 2 * time.Millisecond
	if elapsed < floor {
		t.Errorf("elapsed for %d waits at 1000/s = %v, want at least %v", n, elapsed, floor)
	}
}

func TestLimiterWaitCancelledContext(t *testing.T) {
	t.Parallel()

	// A very slow rate so the ticker will not fire during the test.
	l := NewLimiter(1)
	if l == nil {
		t.Fatal("NewLimiter(1) = nil, want non-nil")
	}
	defer l.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- l.Wait(ctx) }()

	select {
	case err := <-done:
		if err != ctx.Err() {
			t.Errorf("Wait(cancelled ctx) = %v, want %v", err, ctx.Err())
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Wait(cancelled ctx) did not return promptly")
	}
}

func TestParseDelay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    string
		wantNil bool
		wantErr bool
		wantMin time.Duration
		wantMax time.Duration
	}{
		{
			name:    "empty spec yields nil",
			spec:    "",
			wantNil: true,
		},
		{
			name:    "fixed delay",
			spec:    "0.5",
			wantMin: 500 * time.Millisecond,
			wantMax: 500 * time.Millisecond,
		},
		{
			name:    "range delay",
			spec:    "0.1-0.2",
			wantMin: 100 * time.Millisecond,
			wantMax: 200 * time.Millisecond,
		},
		{
			name:    "inverted range is an error",
			spec:    "0.2-0.1",
			wantErr: true,
		},
		{
			name:    "garbage is an error",
			spec:    "abc",
			wantErr: true,
		},
		{
			name:    "negative is an error",
			spec:    "-1",
			wantErr: true,
		},
		{
			name:    "zero yields nil",
			spec:    "0",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, err := ParseDelay(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseDelay(%q) = %+v, want error", tt.spec, d)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDelay(%q) unexpected error: %v", tt.spec, err)
			}
			if tt.wantNil {
				if d != nil {
					t.Fatalf("ParseDelay(%q) = %+v, want nil", tt.spec, d)
				}
				return
			}
			if d == nil {
				t.Fatalf("ParseDelay(%q) = nil, want non-nil", tt.spec)
			}
			if d.min != tt.wantMin || d.max != tt.wantMax {
				t.Errorf("ParseDelay(%q) = {min:%v max:%v}, want {min:%v max:%v}",
					tt.spec, d.min, d.max, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestDelayDurationNil(t *testing.T) {
	t.Parallel()

	var d *Delay
	if got := d.Duration(); got != 0 {
		t.Errorf("nil Delay.Duration() = %v, want 0", got)
	}
}

func TestDelayDurationFixed(t *testing.T) {
	t.Parallel()

	d, err := ParseDelay("0.05")
	if err != nil {
		t.Fatalf("ParseDelay: %v", err)
	}
	want := 50 * time.Millisecond
	for i := 0; i < 10; i++ {
		if got := d.Duration(); got != want {
			t.Errorf("fixed Delay.Duration() = %v, want exactly %v", got, want)
		}
	}
}

func TestDelayDurationRange(t *testing.T) {
	t.Parallel()

	d, err := ParseDelay("0.01-0.03")
	if err != nil {
		t.Fatalf("ParseDelay: %v", err)
	}
	min, max := 10*time.Millisecond, 30*time.Millisecond
	for i := 0; i < 200; i++ {
		got := d.Duration()
		if got < min || got > max {
			t.Fatalf("range Delay.Duration() = %v, want within [%v,%v]", got, min, max)
		}
	}
}

func TestDelaySleepCancelledContext(t *testing.T) {
	t.Parallel()

	d, err := ParseDelay("0.2")
	if err != nil {
		t.Fatalf("ParseDelay: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err = d.Sleep(ctx)
	elapsed := time.Since(start)

	if err != ctx.Err() {
		t.Errorf("Sleep(cancelled ctx) = %v, want %v", err, ctx.Err())
	}
	// Should return promptly, well under the configured 200ms delay.
	if elapsed >= 200*time.Millisecond {
		t.Errorf("Sleep(cancelled ctx) took %v, want it to return before the full delay elapses", elapsed)
	}
}
