package session

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLifetimeSampler_Empty(t *testing.T) {
	s := NewLifetimeSampler(5 * time.Second)
	avg, count := s.Average()
	assert.Equal(t, time.Duration(0), avg)
	assert.Equal(t, 0, count)
}

func TestLifetimeSampler_BasicAverage(t *testing.T) {
	s := NewLifetimeSampler(10 * time.Second)
	s.Record(100 * time.Millisecond)
	s.Record(200 * time.Millisecond)
	s.Record(300 * time.Millisecond)
	avg, count := s.Average()
	assert.Equal(t, 3, count)
	assert.Equal(t, 200*time.Millisecond, avg)
}

func TestLifetimeSampler_SingleSample(t *testing.T) {
	s := NewLifetimeSampler(5 * time.Second)
	s.Record(500 * time.Millisecond)
	avg, count := s.Average()
	assert.Equal(t, 1, count)
	assert.Equal(t, 500*time.Millisecond, avg)
}

func TestLifetimeSampler_ExpiredSamplesDropped(t *testing.T) {
	s := &LifetimeSampler{
		samples: make([]lifetimeSample, 0, 16),
		window:  100 * time.Millisecond,
	}
	// Manually inject an expired sample
	s.samples = append(s.samples, lifetimeSample{
		t:   time.Now().Add(-200 * time.Millisecond),
		dur: 999 * time.Millisecond,
	})
	// Add a fresh sample
	s.Record(50 * time.Millisecond)

	avg, count := s.Average()
	assert.Equal(t, 1, count, "expired sample should be dropped")
	assert.Equal(t, 50*time.Millisecond, avg)
}

func TestLifetimeSampler_Concurrent(t *testing.T) {
	s := NewLifetimeSampler(5 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Record(100 * time.Millisecond)
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Average()
		}()
	}
	wg.Wait()
	_, count := s.Average()
	assert.Equal(t, 50, count)
}
