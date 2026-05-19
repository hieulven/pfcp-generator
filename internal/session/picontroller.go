package session

import "time"

// PIController is a critically-damped PI controller with anti-windup.
//
// Tuning: given a first-order plant with gain K_plant and a desired closed-loop
// time constant τ, critical damping is achieved with:
//
//	Kp = 1 / (2 × τ × K_plant)
//	Ki = Kp / τ
//
// K_plant and τ are passed to Update() each tick (gain scheduling), so the
// controller adapts to plant changes (e.g., observed TPS shifts).
//
// Anti-windup: when the output saturates (or backlog signals throughput
// limitation), the integral term is frozen for that tick — error continues
// to be observed but does not accumulate.
type PIController struct {
	integral  float64
	output    time.Duration
	outputMin time.Duration
	outputMax time.Duration
}

// NewPIController returns a controller with output bounded to [min, max] and
// initial output = 0.
func NewPIController(min, max time.Duration) *PIController {
	return &PIController{
		outputMin: min,
		outputMax: max,
	}
}

// Update computes the next output. Call once per tick.
//
//   - observed — current observed value of the controlled variable
//   - target — desired value
//   - plantGain — ∂(controlled variable)/∂(output), units: per second-of-output
//   - tau — desired closed-loop time constant (seconds)
//   - dt — tick interval (seconds)
//   - freezeIntegral — caller signals external saturation; skip integral accumulation
//
// Returns the new output value, clamped to [outputMin, outputMax].
func (c *PIController) Update(observed, target float64, plantGain, tau, dt float64, freezeIntegral bool) time.Duration {
	if plantGain <= 0 || tau <= 0 {
		return c.output
	}
	kp := 1.0 / (2.0 * tau * plantGain)
	ki := kp / tau
	err := target - observed
	proposedIntegral := c.integral + err*dt

	// Compute tentative output with proposed integral
	proposed := kp*err + ki*proposedIntegral
	proposedOut := time.Duration(proposed * float64(time.Second))

	// Anti-windup: freeze integral if saturating or external freeze requested
	saturatingHigh := proposedOut > c.outputMax && err > 0
	saturatingLow := proposedOut < c.outputMin && err < 0
	if !freezeIntegral && !saturatingHigh && !saturatingLow {
		c.integral = proposedIntegral
	}

	// Recompute with possibly-unchanged integral and clamp
	out := kp*err + ki*c.integral
	outDur := time.Duration(out * float64(time.Second))
	if outDur > c.outputMax {
		outDur = c.outputMax
	} else if outDur < c.outputMin {
		outDur = c.outputMin
	}
	c.output = outDur
	return outDur
}

// State returns current internal state for observability.
func (c *PIController) State() (output time.Duration, integral float64) {
	return c.output, c.integral
}

// IsSaturated returns true if the last output hit either rail.
func (c *PIController) IsSaturated() bool {
	return c.output >= c.outputMax || c.output <= c.outputMin
}

// Reset clears integral and output state. Use on configuration change.
func (c *PIController) Reset() {
	c.integral = 0
	c.output = 0
}
