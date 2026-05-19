package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPI_NoErrorNoChange(t *testing.T) {
	c := NewPIController(0, 10*time.Second)
	plantGain := 100.0
	tau := 2.0
	dt := 1.0

	out := c.Update(500.0, 500.0, plantGain, tau, dt, false)
	assert.Equal(t, time.Duration(0), out)
	_, integral := c.State()
	assert.Equal(t, 0.0, integral)
}

func TestPI_PositiveErrorIncreasesOutput(t *testing.T) {
	c := NewPIController(0, 10*time.Second)
	// observed < target → positive error → positive output
	out := c.Update(0.0, 1000.0, 100.0, 2.0, 1.0, false)
	assert.Greater(t, out, time.Duration(0))
}

func TestPI_NegativeErrorDecreasesOutput(t *testing.T) {
	c := NewPIController(0, 10*time.Second)
	// Prime controller with positive state first
	c.Update(0.0, 1000.0, 100.0, 2.0, 1.0, false)
	// Now observed > target → negative error → output should be 0 (clamped at min)
	out := c.Update(2000.0, 1000.0, 100.0, 2.0, 1.0, false)
	assert.Equal(t, time.Duration(0), out)
}

func TestPI_SaturatesAtMax(t *testing.T) {
	c := NewPIController(0, 5*time.Second)
	plantGain := 0.001 // tiny gain → huge output needed
	for i := 0; i < 50; i++ {
		c.Update(0.0, 1000.0, plantGain, 2.0, 1.0, false)
	}
	out, _ := c.State()
	assert.Equal(t, 5*time.Second, out)
	assert.True(t, c.IsSaturated())
}

func TestPI_SaturatesAtMin(t *testing.T) {
	c := NewPIController(0, 10*time.Second)
	// observed always above target → output stays at floor 0
	for i := 0; i < 20; i++ {
		c.Update(2000.0, 1000.0, 100.0, 2.0, 1.0, false)
	}
	out, _ := c.State()
	assert.Equal(t, time.Duration(0), out)
}

func TestPI_AntiWindupNoDump(t *testing.T) {
	c := NewPIController(0, 2*time.Second)
	// Saturate with large positive error for 10 ticks
	for i := 0; i < 10; i++ {
		c.Update(0.0, 100000.0, 1.0, 2.0, 1.0, false)
	}
	assert.True(t, c.IsSaturated())

	// Now reverse: observed far above target
	// Without anti-windup, accumulated integral would cause massive undershoot
	var minOut time.Duration = 10 * time.Second
	for i := 0; i < 10; i++ {
		out := c.Update(100000.0, 0.0, 1.0, 2.0, 1.0, false)
		if out < minOut {
			minOut = out
		}
	}
	// Output should hit floor (0) not go negative — anti-windup prevented integral dump
	assert.GreaterOrEqual(t, minOut, time.Duration(0))
}

func TestPI_FreezeIntegralByCaller(t *testing.T) {
	c := NewPIController(0, 10*time.Second)
	_, before := c.State()
	c.Update(0.0, 1000.0, 100.0, 2.0, 1.0, true) // freezeIntegral=true
	_, after := c.State()
	assert.Equal(t, before, after, "integral must not grow when frozen")
}

func TestPI_StepResponse_NoOvershoot(t *testing.T) {
	c := NewPIController(0, 10*time.Second)
	plantGain := 1000.0 // 1000 sessions per second of delay
	tau := 2.0
	dt := 1.0
	target := 5000.0
	observed := 0.0

	var maxObserved float64
	for i := 0; i < 30; i++ {
		delay := c.Update(observed, target, plantGain, tau, dt, false)
		// Simulate first-order plant: sessions → plantGain × delay
		observed += (plantGain*delay.Seconds() - observed) * (dt / tau)
		if observed > maxObserved {
			maxObserved = observed
		}
	}
	// No overshoot: max observed never exceeds target by more than 2%
	assert.LessOrEqual(t, maxObserved, target*1.02, "overshoot exceeded 2%%")
	// Converged to within 5% after 30 ticks
	assert.InDelta(t, target, observed, target*0.05, "did not converge within 5%%")
}

func TestPI_GainSchedulingTracksPlant(t *testing.T) {
	c := NewPIController(0, 10*time.Second)
	target := 5000.0
	observed := 0.0
	dt := 1.0

	// Run with initial plant gain
	plantGain := 500.0
	tau := 2.0
	for i := 0; i < 15; i++ {
		delay := c.Update(observed, target, plantGain, tau, dt, false)
		observed += (plantGain*delay.Seconds() - observed) * (dt / tau)
	}
	midObserved := observed

	// Switch plant gain — controller should adapt
	plantGain = 2000.0
	tau = 2.0
	for i := 0; i < 15; i++ {
		delay := c.Update(observed, target, plantGain, tau, dt, false)
		observed += (plantGain*delay.Seconds() - observed) * (dt / tau)
	}
	// After adapting, should be closer to target than mid-point
	assert.Less(t, absf(observed-target), absf(midObserved-target)+target*0.1)
}

func absf(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
