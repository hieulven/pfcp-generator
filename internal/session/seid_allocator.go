package session

import (
	"fmt"
	"math/rand"
	"sync"
)

// SEIDAllocator manages allocation and release of SEIDs.
type SEIDAllocator struct {
	strategy  string
	nextSEID  uint64
	usedSEIDs map[uint64]bool
	mu        sync.Mutex
}

// NewSEIDAllocator creates a new SEID allocator with the given strategy and start value.
func NewSEIDAllocator(strategy string, startSEID uint64) *SEIDAllocator {
	if startSEID == 0 {
		startSEID = 1 // SEID 0 is reserved
	}
	return &SEIDAllocator{
		strategy:  strategy,
		nextSEID:  startSEID,
		usedSEIDs: make(map[uint64]bool),
	}
}

// Allocate returns a new unique SEID.
func (s *SEIDAllocator) Allocate() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.strategy {
	case "sequential":
		for i := 0; i < 1000000; i++ {
			if s.nextSEID == 0 {
				s.nextSEID = 1
			}
			seid := s.nextSEID
			s.nextSEID++
			if !s.usedSEIDs[seid] {
				s.usedSEIDs[seid] = true
				return seid, nil
			}
		}
		return 0, fmt.Errorf("failed to allocate sequential SEID: too many collisions")
	case "random":
		for attempts := 0; attempts < 10000; attempts++ {
			seid := rand.Uint64()
			if seid == 0 || s.usedSEIDs[seid] {
				continue
			}
			s.usedSEIDs[seid] = true
			return seid, nil
		}
		return 0, fmt.Errorf("failed to allocate random SEID after 10000 attempts")
	default:
		return 0, fmt.Errorf("unknown SEID strategy: %s", s.strategy)
	}
}

// Release frees a previously allocated SEID for reuse.
func (s *SEIDAllocator) Release(seid uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.usedSEIDs, seid)
}

// AllocatedCount returns the number of currently allocated SEIDs.
func (s *SEIDAllocator) AllocatedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.usedSEIDs)
}
