package session

import (
	"fmt"
	"net"
	"sync"
)

// UEIPPool manages allocation of UE IP addresses from a CIDR range.
type UEIPPool struct {
	cidr      *net.IPNet
	nextIP    net.IP
	allocated map[string]bool
	mu        sync.Mutex
}

// NewUEIPPool creates a new UE IP pool from a CIDR string (e.g., "10.60.0.0/24").
func NewUEIPPool(cidr string) (*UEIPPool, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	// Start from first usable address (network address + 1)
	firstIP := make(net.IP, len(ipnet.IP))
	copy(firstIP, ipnet.IP)
	incrementIP(firstIP)

	return &UEIPPool{
		cidr:      ipnet,
		nextIP:    firstIP,
		allocated: make(map[string]bool),
	}, nil
}

// Allocate returns the next available IP address from the pool.
func (p *UEIPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Ensure nextIP is within CIDR before starting
	if !p.cidr.Contains(p.nextIP) {
		copy(p.nextIP, p.cidr.IP)
		incrementIP(p.nextIP)
	}

	startIP := make(net.IP, len(p.nextIP))
	copy(startIP, p.nextIP)
	checked := 0

	// Calculate total usable IPs in the CIDR
	ones, bits := p.cidr.Mask.Size()
	totalIPs := 1 << (bits - ones)

	for {
		ipStr := p.nextIP.String()
		if !p.allocated[ipStr] {
			p.allocated[ipStr] = true
			result := make(net.IP, len(p.nextIP))
			copy(result, p.nextIP)
			incrementIP(p.nextIP)
			// Wrap if needed for next call
			if !p.cidr.Contains(p.nextIP) {
				copy(p.nextIP, p.cidr.IP)
				incrementIP(p.nextIP)
			}
			return result, nil
		}

		incrementIP(p.nextIP)
		checked++

		// Wrap around if we've gone past the end
		if !p.cidr.Contains(p.nextIP) {
			copy(p.nextIP, p.cidr.IP)
			incrementIP(p.nextIP)
		}

		// If we've checked all IPs in the range, the pool is exhausted
		if checked >= totalIPs-1 || p.nextIP.Equal(startIP) {
			return nil, fmt.Errorf("UE IP pool exhausted (all %d addresses allocated)", len(p.allocated))
		}
	}
}

// Release frees a previously allocated IP address back to the pool.
func (p *UEIPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allocated, ip.String())
}

// AllocatedCount returns the number of currently allocated IPs.
func (p *UEIPPool) AllocatedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.allocated)
}

// Available returns the approximate number of available IPs.
func (p *UEIPPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	ones, bits := p.cidr.Mask.Size()
	total := 1 << (bits - ones)
	avail := total - len(p.allocated) - 2 // subtract network and broadcast
	if avail < 0 {
		return 0
	}
	return avail
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
