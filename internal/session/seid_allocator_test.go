package session

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSEIDAllocator_Sequential_StartsFromBase(t *testing.T) {
	alloc := NewSEIDAllocator("sequential", 100)
	seid, err := alloc.Allocate()
	require.NoError(t, err)
	assert.Equal(t, uint64(100), seid)
}

func TestSEIDAllocator_Sequential_Increments(t *testing.T) {
	alloc := NewSEIDAllocator("sequential", 1)
	seid1, err := alloc.Allocate()
	require.NoError(t, err)
	seid2, err := alloc.Allocate()
	require.NoError(t, err)
	seid3, err := alloc.Allocate()
	require.NoError(t, err)

	assert.Equal(t, uint64(1), seid1)
	assert.Equal(t, uint64(2), seid2)
	assert.Equal(t, uint64(3), seid3)
}

func TestSEIDAllocator_Sequential_SkipsZero(t *testing.T) {
	alloc := NewSEIDAllocator("sequential", 0)
	seid, err := alloc.Allocate()
	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), seid)
	assert.Equal(t, uint64(1), seid)
}

func TestSEIDAllocator_Random_NeverZero(t *testing.T) {
	alloc := NewSEIDAllocator("random", 1)
	for i := 0; i < 100; i++ {
		seid, err := alloc.Allocate()
		require.NoError(t, err)
		assert.NotEqual(t, uint64(0), seid)
		alloc.Release(seid)
	}
}

func TestSEIDAllocator_Random_NoDuplicates(t *testing.T) {
	alloc := NewSEIDAllocator("random", 1)
	seen := make(map[uint64]bool)
	for i := 0; i < 100; i++ {
		seid, err := alloc.Allocate()
		require.NoError(t, err)
		assert.False(t, seen[seid], "duplicate SEID allocated: %d", seid)
		seen[seid] = true
	}
}

func TestSEIDAllocator_Release_AllowsReuse(t *testing.T) {
	alloc := NewSEIDAllocator("sequential", 1)
	seid1, err := alloc.Allocate()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), seid1)

	alloc.Release(seid1)
	assert.Equal(t, 0, alloc.AllocatedCount())
}

func TestSEIDAllocator_UnknownStrategy(t *testing.T) {
	alloc := NewSEIDAllocator("unknown", 1)
	_, err := alloc.Allocate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown SEID strategy")
}

func TestSEIDAllocator_ConcurrentAccess(t *testing.T) {
	alloc := NewSEIDAllocator("sequential", 1)
	var wg sync.WaitGroup
	results := make(chan uint64, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seid, err := alloc.Allocate()
			require.NoError(t, err)
			results <- seid
		}()
	}

	wg.Wait()
	close(results)

	seen := make(map[uint64]bool)
	for seid := range results {
		assert.False(t, seen[seid], "duplicate SEID in concurrent allocation: %d", seid)
		seen[seid] = true
	}
	assert.Equal(t, 100, len(seen))
}
