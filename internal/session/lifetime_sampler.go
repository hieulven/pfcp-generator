package session

import (
	"sync"
	"time"
)

// LifetimeSampler maintains a moving-average of session base lifetimes.
// "Base lifetime" = time from session creation to entering the deletion queue
// (establish + modifications + RTTs, excluding pre-deletion delay).
type LifetimeSampler struct {
	mu      sync.Mutex
	samples []lifetimeSample
	window  time.Duration
}

type lifetimeSample struct {
	t   time.Time
	dur time.Duration
}

// NewLifetimeSampler creates a sampler with the given moving-average window.
func NewLifetimeSampler(window time.Duration) *LifetimeSampler {
	return &LifetimeSampler{
		samples: make([]lifetimeSample, 0, 1024),
		window:  window,
	}
}

// Record adds a base-lifetime sample.
func (s *LifetimeSampler) Record(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples = append(s.samples, lifetimeSample{t: time.Now(), dur: d})
}

// Average returns the average of samples within the window and the sample count.
// Returns (0, 0) when no samples are in window.
func (s *LifetimeSampler) Average() (time.Duration, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-s.window)
	// Drop expired samples from the front (samples are appended in time order)
	i := 0
	for i < len(s.samples) && s.samples[i].t.Before(cutoff) {
		i++
	}
	if i > 0 {
		s.samples = s.samples[i:]
	}
	if len(s.samples) == 0 {
		return 0, 0
	}
	var total time.Duration
	for _, smp := range s.samples {
		total += smp.dur
	}
	return total / time.Duration(len(s.samples)), len(s.samples)
}
