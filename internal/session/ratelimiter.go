package session

import (
	"context"
	"math"
	"sync/atomic"
	"time"
)

// RateLimiter controls the rate of operations using a time-aware batch-ticker.
//
// Supports live TPS changes via SetTPS() without rebuilding the limiter.
// The producer goroutine reads the target TPS atomically each tick.
type RateLimiter struct {
	tokenCh  chan struct{}
	tpsBits  atomic.Uint64 // float64 bits stored as uint64
	epoch    atomic.Uint64 // incremented by SetTPS to signal accounting reset
	cancel   context.CancelFunc
	Dropped  atomic.Int64 // tokens dropped due to full buffer (back-pressure)
}

// NewRateLimiter creates a rate limiter that produces tokens at the given TPS rate.
// If tps <= 0, the limiter is disabled (Wait returns immediately).
func NewRateLimiter(ctx context.Context, tps float64) *RateLimiter {
	if tps <= 0 {
		return &RateLimiter{}
	}

	ctx, cancel := context.WithCancel(ctx)

	// Buffer: 1 full second of tokens at initial TPS.
	// For TPS changes, the buffer may temporarily be too small or large,
	// but the producer self-corrects within one tick interval.
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
	rl.tpsBits.Store(math.Float64bits(tps))

	go func() {
		// Tick at ~1ms for scheduler reliability.
		interval := time.Millisecond
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var produced int64
		start := time.Now()
		lastEpoch := rl.epoch.Load()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Read current TPS atomically — picks up SetTPS() changes.
				currentTPS := math.Float64frombits(rl.tpsBits.Load())
				if currentTPS <= 0 {
					continue
				}

				// Detect TPS change: reset wall-clock accounting so we don't
				// produce a burst to catch up to the old baseline, or stall
				// because produced already exceeds what the new rate expects.
				if curEpoch := rl.epoch.Load(); curEpoch != lastEpoch {
					lastEpoch = curEpoch
					produced = 0
					start = time.Now()
				}

				now := time.Now()
				expected := int64(currentTPS * now.Sub(start).Seconds())
				deficit := expected - produced
				if deficit <= 0 {
					continue
				}
				for i := int64(0); i < deficit; i++ {
					select {
					case tokenCh <- struct{}{}:
					default:
						rl.Dropped.Add(1)
					}
					produced++
				}
			}
		}
	}()

	return rl
}

// SetTPS changes the target TPS at runtime. Takes effect on the next tick (~1ms).
// The producer goroutine detects the epoch change and resets its wall-clock
// accounting to avoid stale deficits that would cause a burst or a stall.
func (r *RateLimiter) SetTPS(tps float64) {
	if tps <= 0 {
		tps = 0
	}
	r.tpsBits.Store(math.Float64bits(tps))
	r.epoch.Add(1) // signal producer to reset accounting
}

// GetTPS returns the current target TPS.
func (r *RateLimiter) GetTPS() float64 {
	return math.Float64frombits(r.tpsBits.Load())
}

// Wait blocks until a token is available or the context is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
	if r.tokenCh == nil {
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
