package control

import (
	"math"
	"sync/atomic"
)

// StressParams holds runtime-tunable stress test parameters.
// All fields are accessed atomically so they can be read by workers
// and written by the control server without locking.
type StressParams struct {
	tps            atomic.Uint64 // float64 bits stored as uint64
	activeSessions atomic.Int64
}

// NewStressParams creates a new StressParams with initial values.
func NewStressParams(tps float64, activeSessions int) *StressParams {
	p := &StressParams{}
	p.SetTPS(tps)
	p.SetActiveSessions(activeSessions)
	return p
}

// SetTPS updates the target TPS.
func (p *StressParams) SetTPS(tps float64) {
	p.tps.Store(math.Float64bits(tps))
}

// GetTPS returns the current target TPS.
func (p *StressParams) GetTPS() float64 {
	return math.Float64frombits(p.tps.Load())
}

// SetActiveSessions updates the max concurrent sessions.
func (p *StressParams) SetActiveSessions(n int) {
	p.activeSessions.Store(int64(n))
}

// GetActiveSessions returns the current max concurrent sessions.
func (p *StressParams) GetActiveSessions() int {
	return int(p.activeSessions.Load())
}