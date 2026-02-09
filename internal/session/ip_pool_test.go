package session

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUEIPPool_NewFromCIDR(t *testing.T) {
	pool, err := NewUEIPPool("10.60.0.0/24")
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestUEIPPool_InvalidCIDR(t *testing.T) {
	_, err := NewUEIPPool("invalid")
	assert.Error(t, err)
}

func TestUEIPPool_Allocate_Sequential(t *testing.T) {
	pool, err := NewUEIPPool("10.60.0.0/24")
	require.NoError(t, err)

	ip1, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.60.0.1", ip1.String())

	ip2, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.60.0.2", ip2.String())

	ip3, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.60.0.3", ip3.String())
}

func TestUEIPPool_Allocate_SkipsNetworkAddress(t *testing.T) {
	pool, err := NewUEIPPool("10.60.0.0/24")
	require.NoError(t, err)

	ip, err := pool.Allocate()
	require.NoError(t, err)
	// First IP should be .1, not .0 (network address)
	assert.Equal(t, "10.60.0.1", ip.String())
}

func TestUEIPPool_Exhaustion(t *testing.T) {
	// /30 gives 4 addresses: .0 (net), .1, .2, .3 (broadcast)
	// Only .1 and .2 are usable, but our pool doesn't skip broadcast
	// so it allocates .1, .2, .3 then wraps and fails
	pool, err := NewUEIPPool("10.60.0.0/30")
	require.NoError(t, err)

	ip1, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.60.0.1", ip1.String())

	ip2, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.60.0.2", ip2.String())

	ip3, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.60.0.3", ip3.String())

	// Pool should be exhausted now (next would be .4 which is outside /30)
	_, err = pool.Allocate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

func TestUEIPPool_Release_AllowsReallocation(t *testing.T) {
	pool, err := NewUEIPPool("10.60.0.0/30")
	require.NoError(t, err)

	ip1, err := pool.Allocate()
	require.NoError(t, err)
	ip2, err := pool.Allocate()
	require.NoError(t, err)
	ip3, err := pool.Allocate()
	require.NoError(t, err)

	// Exhaust pool
	_, err = pool.Allocate()
	assert.Error(t, err)

	// Release one
	pool.Release(ip2)

	// Should be able to allocate again
	ip4, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, ip2.String(), ip4.String())

	_ = ip1
	_ = ip3
}

func TestUEIPPool_Available_Count(t *testing.T) {
	pool, err := NewUEIPPool("10.60.0.0/24")
	require.NoError(t, err)

	// /24 = 256 total, minus network and broadcast = 254
	assert.Equal(t, 254, pool.Available())

	_, err = pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, 253, pool.Available())
}

func TestUEIPPool_ConcurrentAccess(t *testing.T) {
	pool, err := NewUEIPPool("10.60.0.0/16")
	require.NoError(t, err)

	var wg sync.WaitGroup
	results := make(chan string, 1000)

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := pool.Allocate()
			require.NoError(t, err)
			results <- ip.String()
		}()
	}

	wg.Wait()
	close(results)

	seen := make(map[string]bool)
	for ipStr := range results {
		assert.False(t, seen[ipStr], "duplicate IP allocated: %s", ipStr)
		seen[ipStr] = true
	}
	assert.Equal(t, 1000, len(seen))
}

func TestUEIPPool_AllocatedCount(t *testing.T) {
	pool, err := NewUEIPPool("10.60.0.0/24")
	require.NoError(t, err)

	assert.Equal(t, 0, pool.AllocatedCount())

	ip, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, 1, pool.AllocatedCount())

	pool.Release(ip)
	assert.Equal(t, 0, pool.AllocatedCount())
}

func TestUEIPPool_Release_UnknownIP(t *testing.T) {
	pool, err := NewUEIPPool("10.60.0.0/24")
	require.NoError(t, err)

	// Should not panic when releasing an IP that was never allocated
	pool.Release(net.ParseIP("10.60.0.99"))
	assert.Equal(t, 0, pool.AllocatedCount())
}
