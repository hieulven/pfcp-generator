package session

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

// IPAllocator is the interface for UE IP allocation used by the session manager.
type IPAllocator interface {
	Allocate() (net.IP, error)
	Release(ip net.IP)
	Available() int
	AllocatedCount() int
	TotalIPs() int
}

// UEIPPool manages allocation of UE IP addresses from a CIDR range.
// Uses a FIFO ring buffer so that recently released IPs go to the back
// of the queue and are not reused immediately. This gives the UPF time
// to clean up stale session state before the IP appears again.
type UEIPPool struct {
	baseIP    uint32   // network address as uint32
	ring      []uint32 // FIFO ring buffer of available IP offsets
	head      int      // next slot to read (allocate from)
	tail      int      // next slot to write (release into)
	count     int      // number of available IPs in the ring
	allocated []bool   // tracks which offsets are in use
	totalIPs  int      // total usable IPs (excluding network address)
	mu        sync.Mutex
}

// NewUEIPPool creates a new UE IP pool from a CIDR string (e.g., "10.60.0.0/24").
func NewUEIPPool(cidr string) (*UEIPPool, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDR is supported, got %q", cidr)
	}

	baseIP := binary.BigEndian.Uint32(ip4)
	ones, bits := ipnet.Mask.Size()
	totalAddrs := 1 << (bits - ones)

	// Skip network address (.0), so usable = totalAddrs - 1
	usable := totalAddrs - 1
	if usable <= 0 {
		usable = 1
	}

	// Populate ring in sequential order: offset 1 at head, offset usable at tail-1.
	// First Allocate() returns .1, second returns .2, etc.
	ring := make([]uint32, usable)
	for i := 0; i < usable; i++ {
		ring[i] = uint32(i + 1) // offsets 1, 2, ..., usable
	}

	// Tracking array: offset 0 unused (network addr), offsets 1..usable
	allocated := make([]bool, usable+1)

	return &UEIPPool{
		baseIP:    baseIP,
		ring:      ring,
		head:      0,
		tail:      0,
		count:     usable,
		allocated: allocated,
		totalIPs:  usable,
	}, nil
}

// Allocate returns the next available IP address from the pool. O(1).
// IPs are returned in FIFO order — the longest-unused IP is allocated first.
func (p *UEIPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	if p.count == 0 {
		p.mu.Unlock()
		return nil, fmt.Errorf("UE IP pool exhausted (all %d addresses allocated)", p.totalIPs)
	}
	offset := p.ring[p.head]
	p.head = (p.head + 1) % len(p.ring)
	p.count--
	p.allocated[offset] = true
	remaining := p.count
	p.mu.Unlock()

	ip := uint32ToIP(p.baseIP + offset)
	log.WithFields(log.Fields{
		"ip":        ip,
		"available": remaining,
	}).Debug("UE IP allocated")

	return ip, nil
}

// Release frees a previously allocated IP address back to the pool. O(1).
// The IP is placed at the back of the FIFO queue so it won't be reused
// until all other available IPs have been allocated first.
func (p *UEIPPool) Release(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	ipVal := binary.BigEndian.Uint32(ip4)
	if ipVal < p.baseIP {
		return
	}
	offset := ipVal - p.baseIP

	p.mu.Lock()
	if int(offset) < len(p.allocated) && p.allocated[offset] {
		p.allocated[offset] = false
		p.ring[p.tail] = uint32(offset)
		p.tail = (p.tail + 1) % len(p.ring)
		p.count++
		remaining := p.count
		p.mu.Unlock()

		log.WithFields(log.Fields{
			"ip":        ip,
			"available": remaining,
		}).Debug("UE IP released")
		return
	}
	p.mu.Unlock()
}

// AllocatedCount returns the number of currently allocated IPs.
func (p *UEIPPool) AllocatedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalIPs - p.count
}

// Available returns the number of available IPs.
func (p *UEIPPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

// TotalIPs returns the total number of usable IPs in the pool.
func (p *UEIPPool) TotalIPs() int {
	return p.totalIPs
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

// MultiUEIPPool aggregates multiple UEIPPool instances into a single shared
// FIFO ring buffer. At construction time, all IPs from all pools are drained
// into the shared FIFO. There is only one source for allocation and one
// destination for release — no fresh/recycled split, no races.
//
// Released IPs go to the back of the global FIFO, giving maximum cooldown
// time before reuse regardless of which pool the IP belongs to.
type MultiUEIPPool struct {
	pools    []*UEIPPool // kept for allocated[] tracking only
	ring     []net.IP    // shared FIFO ring buffer — the only source of IPs
	head     int
	tail     int
	count    int
	totalIPs int
	mu       sync.Mutex
}

// NewMultiUEIPPool creates a pool that spans multiple CIDR ranges.
// All IPs from all pools are pre-populated into a single shared FIFO
// in sequential order across pools.
func NewMultiUEIPPool(cidrs []string) (*MultiUEIPPool, error) {
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("at least one CIDR is required")
	}
	pools := make([]*UEIPPool, 0, len(cidrs))
	totalIPs := 0
	for _, cidr := range cidrs {
		p, err := NewUEIPPool(cidr)
		if err != nil {
			return nil, fmt.Errorf("failed to create pool for %q: %w", cidr, err)
		}
		pools = append(pools, p)
		totalIPs += p.TotalIPs()
	}

	// Drain all IPs from all pools into the shared FIFO.
	ring := make([]net.IP, totalIPs)
	idx := 0
	for _, p := range pools {
		for {
			ip, err := p.Allocate()
			if err != nil {
				break // pool exhausted
			}
			ring[idx] = ip
			idx++
		}
	}

	log.WithFields(log.Fields{
		"pools":    len(pools),
		"total_ips": totalIPs,
		"loaded":   idx,
	}).Info("Multi-pool: all IPs loaded into shared FIFO")

	return &MultiUEIPPool{
		pools:    pools,
		ring:     ring,
		head:     0,
		tail:     0,
		count:    idx,
		totalIPs: totalIPs,
	}, nil
}

// Allocate returns the next available IP from the shared FIFO. O(1).
func (m *MultiUEIPPool) Allocate() (net.IP, error) {
	m.mu.Lock()
	if m.count == 0 {
		m.mu.Unlock()
		return nil, fmt.Errorf("all UE IP pools exhausted (total %d addresses across %d pools)", m.totalIPs, len(m.pools))
	}
	ip := m.ring[m.head]
	m.head = (m.head + 1) % len(m.ring)
	m.count--
	remaining := m.count
	m.mu.Unlock()

	// Mark as allocated in the owning pool's tracking array
	m.markAllocated(ip, true)

	log.WithFields(log.Fields{
		"ip":        ip,
		"available": remaining,
	}).Debug("UE IP allocated (multi-pool)")

	return ip, nil
}

// Release returns an IP to the back of the shared FIFO queue. O(1).
func (m *MultiUEIPPool) Release(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}

	// Mark as not allocated in the owning pool's tracking array
	m.markAllocated(ip, false)

	// Push to shared FIFO — goes to the back of the global queue
	ipCopy := make(net.IP, len(ip4))
	copy(ipCopy, ip4)

	m.mu.Lock()
	m.ring[m.tail] = ipCopy
	m.tail = (m.tail + 1) % len(m.ring)
	m.count++
	queued := m.count
	m.mu.Unlock()

	log.WithFields(log.Fields{
		"ip":     ip,
		"queued": queued,
	}).Debug("UE IP released (multi-pool)")
}

// markAllocated sets or clears the allocated flag in the owning pool.
func (m *MultiUEIPPool) markAllocated(ip net.IP, allocated bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	ipVal := binary.BigEndian.Uint32(ip4)
	for _, p := range m.pools {
		offset := ipVal - p.baseIP
		if offset > 0 && int(offset) < len(p.allocated) {
			p.mu.Lock()
			p.allocated[offset] = allocated
			p.mu.Unlock()
			return
		}
	}
}

// Available returns the number of available IPs in the shared FIFO.
func (m *MultiUEIPPool) Available() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.count
}

// AllocatedCount returns the number of currently allocated IPs.
func (m *MultiUEIPPool) AllocatedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalIPs - m.count
}

// TotalIPs returns the total number of usable IPs across all pools.
func (m *MultiUEIPPool) TotalIPs() int {
	return m.totalIPs
}