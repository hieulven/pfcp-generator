package session

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
)

// SEIDAllocator manages allocation and release of SEIDs.
// For sequential strategy, uses atomic counter + free-list for O(1) allocation.
type SEIDAllocator struct {
	strategy string
	nextSEID atomic.Uint64
	freeList []uint64
	mu       sync.Mutex // protects freeList only
}

// NewSEIDAllocator creates a new SEID allocator with the given strategy and start value.
func NewSEIDAllocator(strategy string, startSEID uint64) *SEIDAllocator {
	if startSEID == 0 {
		startSEID = 1 // SEID 0 is reserved
	}
	s := &SEIDAllocator{
		strategy: strategy,
	}
	s.nextSEID.Store(startSEID)
	return s
}

// Allocate returns a new unique SEID.
func (s *SEIDAllocator) Allocate() (uint64, error) {
	switch s.strategy {
	case "sequential":
		// Fast path: try free-list first
		s.mu.Lock()
		if len(s.freeList) > 0 {
			seid := s.freeList[len(s.freeList)-1]
			s.freeList = s.freeList[:len(s.freeList)-1]
			s.mu.Unlock()
			return seid, nil
		}
		s.mu.Unlock()

		// Lock-free fast path: increment counter
		seid := s.nextSEID.Add(1) - 1
		if seid == 0 {
			// Skip SEID 0
			seid = s.nextSEID.Add(1) - 1
		}
		return seid, nil

	case "random":
		// Random strategy still needs collision check but uses atomic counter as fallback
		for attempts := 0; attempts < 10000; attempts++ {
			seid := rand.Uint64()
			if seid == 0 {
				continue
			}
			return seid, nil
		}
		return 0, fmt.Errorf("failed to allocate random SEID after 10000 attempts")

	default:
		return 0, fmt.Errorf("unknown SEID strategy: %s", s.strategy)
	}
}

// Release frees a previously allocated SEID for reuse.
func (s *SEIDAllocator) Release(seid uint64) {
	if s.strategy != "sequential" {
		return
	}
	s.mu.Lock()
	s.freeList = append(s.freeList, seid)
	s.mu.Unlock()
}

// AllocatedCount returns an approximate count of allocated SEIDs.
// For sequential strategy this is: nextSEID - startSEID - len(freeList).
func (s *SEIDAllocator) AllocatedCount() int {
	s.mu.Lock()
	freeCount := len(s.freeList)
	s.mu.Unlock()
	next := int(s.nextSEID.Load())
	count := next - 1 - freeCount // -1 because nextSEID starts at startSEID
	if count < 0 {
		return 0
	}
	return count
}
