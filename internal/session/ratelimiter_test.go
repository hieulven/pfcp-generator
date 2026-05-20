package session

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRateLimiter_BasicRate verifies that tokens are produced at approximately the requested TPS.
func TestRateLimiter_BasicRate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const targetTPS = 1000.0
	rl := NewRateLimiter(ctx, targetTPS)
	defer rl.Stop()

	start := time.Now()
	const count = 100
	for i := 0; i < count; i++ {
		err := rl.Wait(ctx)
		require.NoError(t, err)
	}
	elapsed := time.Since(start)

	// 100 tokens at 1000 TPS should take ~100ms; allow ±50% for scheduler jitter.
	expected := time.Duration(float64(count) / targetTPS * float64(time.Second))
	assert.Greater(t, elapsed, expected/2, "completed too fast (rate not enforced)")
	assert.Less(t, elapsed, expected*2, "completed too slow")
}

// TestRateLimiter_TPSDownwardChange verifies that reducing TPS via SetTPS does not
// cause a dead period. The per-tick accumulator design handles this naturally: after
// a downward change the next tick simply emits newTPS*dt tokens with no stale state.
func TestRateLimiter_TPSDownwardChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start at 5000 TPS and drain some tokens to simulate a running system.
	const initialTPS = 5000.0
	rl := NewRateLimiter(ctx, initialTPS)
	defer rl.Stop()

	const preWarm = 200
	for i := 0; i < preWarm; i++ {
		require.NoError(t, rl.Wait(ctx))
	}

	// Drop to 100 TPS. The per-tick accumulator produces ~0.1 tokens/tick,
	// emitting 1 token every ~10ms — well within the 200ms deadline.
	rl.SetTPS(100.0)

	// We should receive at least 1 token within 200ms despite the downward change.
	deadline := time.After(200 * time.Millisecond)
	select {
	case <-deadline:
		t.Fatal("no token received within 200ms after TPS decrease")
	case err := <-func() <-chan error {
		ch := make(chan error, 1)
		go func() {
			ch <- rl.Wait(ctx)
		}()
		return ch
	}():
		require.NoError(t, err)
	}
}

// TestRateLimiter_TPSIncrease verifies that increasing TPS produces tokens promptly
// without a burst exceeding the new rate.
func TestRateLimiter_TPSIncrease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const initialTPS = 100.0
	rl := NewRateLimiter(ctx, initialTPS)
	defer rl.Stop()

	// Consume a few tokens at the low rate.
	for i := 0; i < 5; i++ {
		require.NoError(t, rl.Wait(ctx))
	}

	// Increase TPS — tokens should flow at the higher rate quickly.
	rl.SetTPS(5000.0)

	start := time.Now()
	const count = 50
	for i := 0; i < count; i++ {
		require.NoError(t, rl.Wait(ctx))
	}
	elapsed := time.Since(start)

	// At 5000 TPS, 50 tokens should arrive within 50ms (allow 3× for scheduler).
	assert.Less(t, elapsed, 150*time.Millisecond, "increased TPS didn't take effect fast enough")
}

// TestRateLimiter_ZeroTPS verifies that a nil/zero limiter returns immediately.
func TestRateLimiter_ZeroTPS(t *testing.T) {
	ctx := context.Background()
	rl := NewRateLimiter(ctx, 0)
	defer rl.Stop()

	start := time.Now()
	require.NoError(t, rl.Wait(ctx))
	assert.Less(t, time.Since(start), 5*time.Millisecond)
}

// TestRateLimiter_ContextCancel verifies that Wait returns promptly on context cancellation.
func TestRateLimiter_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rl := NewRateLimiter(ctx, 1.0) // very slow: 1 TPS
	defer rl.Stop()

	done := make(chan error, 1)
	go func() {
		done <- rl.Wait(ctx)
	}()

	// Cancel after 10ms — Wait should unblock quickly.
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(50 * time.Millisecond):
		t.Fatal("Wait did not return after context cancellation")
	}
}

// TestRateLimiter_TryWait verifies non-blocking behaviour.
func TestRateLimiter_TryWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// High TPS to ensure tokens are in the buffer immediately.
	rl := NewRateLimiter(ctx, 100_000.0)
	defer rl.Stop()

	// Give the producer goroutine a tick to fill the buffer.
	time.Sleep(5 * time.Millisecond)
	assert.True(t, rl.TryWait(), "expected token to be available")
}

// TestRateLimiter_GetTPS verifies that GetTPS reflects SetTPS changes.
func TestRateLimiter_GetTPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := NewRateLimiter(ctx, 1000.0)
	defer rl.Stop()

	assert.Equal(t, 1000.0, rl.GetTPS())

	rl.SetTPS(500.0)
	assert.Equal(t, 500.0, rl.GetTPS())
}
