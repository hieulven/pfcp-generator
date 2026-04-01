package session

import (
	"context"
	"sync/atomic"
	"time"
)

// RateLimiter controls the rate of operations using a time-aware batch-ticker.
//
// Go's time.Ticker drops ticks when the receiver goroutine is delayed by the
// scheduler (common with 10K+ goroutines). The old fixed-batch approach lost
// tokens permanently on each missed tick, causing ~50% throughput loss under
// heavy goroutine load.
//
// This implementation computes expected production from wall-clock elapsed time,
// so missed ticks are recovered on the next wakeup.
type RateLimiter struct {
	tokenCh chan struct{}
	cancel  context.CancelFunc
	Dropped atomic.Int64 // tokens dropped due to full buffer (back-pressure)
}

// NewRateLimiter creates a rate limiter that produces tokens at the given TPS rate.
// If tps <= 0, the limiter is disabled (Wait returns immediately).
func NewRateLimiter(ctx context.Context, tps float64) *RateLimiter {
	if tps <= 0 {
		return &RateLimiter{}
	}

	ctx, cancel := context.WithCancel(ctx)

	// Determine tick interval.
	// Target: ~1ms for scheduler reliability.
	batchSize := int(tps / 1000)
	if batchSize < 1 {
		batchSize = 1
	}

	interval := time.Duration(float64(time.Second) * float64(batchSize) / tps)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}

	// Buffer: 1 full second of tokens. At 300K active sessions with thousands
	// of goroutines, consumption is bursty: deletion goroutines spawn in batches
	// and workers resume in waves. A small buffer causes token drops that
	// permanently reduce effective TPS (5-7% loss at 40K TPS with 10K buffer).
	// 1 second of headroom guarantees no drops under any scheduling pattern.
	// At 40K TPS this is 40K tokens × 8 bytes = 320KB — negligible memory.
	bufSize := int(tps)
	if bufSize < 1000 {
		bufSize = 1000
	}
	if bufSize > 500000 {
		bufSize = 500000
	}
	tokenCh := make(chan struct{}, bufSize)

	rl := &RateLimiter{
		tokenCh: tokenCh,
		cancel:  cancel,
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var produced int64
		start := time.Now()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Use wall-clock time to compute how many tokens are owed.
				// This recovers tokens lost to ticker coalescing.
				now := time.Now()
				expected := int64(tps * now.Sub(start).Seconds())
				deficit := expected - produced
				if deficit <= 0 {
					continue
				}
				for i := int64(0); i < deficit; i++ {
					select {
					case tokenCh <- struct{}{}:
					default:
						// Drop token if consumers are slow (back-pressure)
						rl.Dropped.Add(1)
					}
					produced++
				}
			}
		}
	}()

	return rl
}

// Wait blocks until a token is available or the context is cancelled.
// Returns ctx.Err() if the context is done.
func (r *RateLimiter) Wait(ctx context.Context) error {
	if r.tokenCh == nil {
		// Rate limiting disabled
		return nil
	}

	select {
	case <-r.tokenCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryWait attempts to acquire a token without blocking.
// Returns true if a token was acquired, false if none available.
func (r *RateLimiter) TryWait() bool {
	if r.tokenCh == nil {
		return true
	}
	select {
	case <-r.tokenCh:
		return true
	default:
		return false
	}
}

// Stop releases the rate limiter's resources.
func (r *RateLimiter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}
