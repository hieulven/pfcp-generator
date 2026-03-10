package session

import (
	"context"
	"time"
)

// RateLimiter controls the rate of operations using a batch-ticker approach.
// At high TPS (e.g. 50K), individual tickers at 20µs are unreliable.
// Instead, we produce tokens in batches at ~1ms intervals.
type RateLimiter struct {
	tokenCh chan struct{}
	cancel  context.CancelFunc
}

// NewRateLimiter creates a rate limiter that produces tokens at the given TPS rate.
// If tps <= 0, the limiter is disabled (Wait returns immediately).
func NewRateLimiter(ctx context.Context, tps float64) *RateLimiter {
	if tps <= 0 {
		return &RateLimiter{}
	}

	ctx, cancel := context.WithCancel(ctx)

	// Determine batch size and interval.
	// Target: batch interval >= 1ms for scheduler reliability.
	batchSize := int(tps / 1000)
	if batchSize < 1 {
		batchSize = 1
	}

	interval := time.Duration(float64(time.Second) * float64(batchSize) / tps)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}

	// Buffer: 2× batch size to absorb jitter
	bufSize := batchSize * 2
	if bufSize < 100 {
		bufSize = 100
	}
	tokenCh := make(chan struct{}, bufSize)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for i := 0; i < batchSize; i++ {
					select {
					case tokenCh <- struct{}{}:
					default:
						// Drop token if consumers are slow (back-pressure)
					}
				}
			}
		}
	}()

	return &RateLimiter{
		tokenCh: tokenCh,
		cancel:  cancel,
	}
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

// Stop releases the rate limiter's resources.
func (r *RateLimiter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}
