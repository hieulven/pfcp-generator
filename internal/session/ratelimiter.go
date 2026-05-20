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
// The producer goroutine reads the target TPS atomically each tick and emits
// tokens based only on the elapsed time since the last tick (per-tick deficit),
// so TPS changes take effect immediately without accumulated state or resets.
type RateLimiter struct {
	tokenCh chan struct{}
	tpsBits atomic.Uint64 // float64 bits stored as uint64
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
		interval := time.Millisecond
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		lastTick := time.Now()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				currentTPS := math.Float64frombits(rl.tpsBits.Load())
				if currentTPS <= 0 {
					lastTick = now
					continue
				}
				dt := now.Sub(lastTick).Seconds()
				lastTick = now
				toEmit := int64(currentTPS * dt)
				if toEmit <= 0 {
					continue
				}
				for i := int64(0); i < toEmit; i++ {
					select {
					case tokenCh <- struct{}{}:
					default:
						rl.Dropped.Add(1)
					}
				}
			}
		}
	}()

	return rl
}

// SetTPS changes the target TPS at runtime. Takes effect on the next tick (~1ms).
// Because the producer uses per-tick accounting, no reset is needed — the next
// tick simply computes toEmit = newTPS * dt with no accumulated state to clear.
func (r *RateLimiter) SetTPS(tps float64) {
	if tps <= 0 {
		tps = 0
	}
	r.tpsBits.Store(math.Float64bits(tps))
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
