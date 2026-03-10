package session

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// UEIPPool manages allocation of UE IP addresses from a CIDR range.
// Uses a free-list stack for O(1) allocation and release, with uint32 offsets
// instead of string-keyed maps.
type UEIPPool struct {
	baseIP    uint32   // network address as uint32
	freeList  []uint32 // stack of available IP offsets
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

	// Pre-populate free list in reverse order so that offset 1 (.1) is at top of stack
	freeList := make([]uint32, usable)
	for i := 0; i < usable; i++ {
		freeList[i] = uint32(usable - i) // [usable, usable-1, ..., 2, 1]
	}

	// Tracking array: offset 0 unused (network addr), offsets 1..usable
	allocated := make([]bool, usable+1)

	return &UEIPPool{
		baseIP:    baseIP,
		freeList:  freeList,
		allocated: allocated,
		totalIPs:  usable,
	}, nil
}

// Allocate returns the next available IP address from the pool. O(1).
func (p *UEIPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	if len(p.freeList) == 0 {
		p.mu.Unlock()
		return nil, fmt.Errorf("UE IP pool exhausted (all %d addresses allocated)", p.totalIPs)
	}
	offset := p.freeList[len(p.freeList)-1]
	p.freeList = p.freeList[:len(p.freeList)-1]
	p.allocated[offset] = true
	p.mu.Unlock()

	return uint32ToIP(p.baseIP + offset), nil
}

// Release frees a previously allocated IP address back to the pool. O(1).
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
	// Only release if it was actually allocated
	if int(offset) < len(p.allocated) && p.allocated[offset] {
		p.allocated[offset] = false
		p.freeList = append(p.freeList, uint32(offset))
	}
	p.mu.Unlock()
}

// AllocatedCount returns the number of currently allocated IPs.
func (p *UEIPPool) AllocatedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalIPs - len(p.freeList)
}

// Available returns the number of available IPs.
func (p *UEIPPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.freeList)
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
