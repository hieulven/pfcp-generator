package network

import (
	"fmt"
	"net"
	"sync/atomic"
)

// UDPClientPool manages multiple UDP clients for multi-source-port sending.
// Sends are distributed across clients using round-robin.
type UDPClientPool struct {
	clients []*UDPClient
	counter atomic.Uint64
}

// NewUDPClientPool creates a pool of UDP clients on sequential ports.
// Port range: [smfPort, smfPort+numPorts-1].
func NewUDPClientPool(smfAddr string, smfPort int, upfAddr string, upfPort int, numPorts int) (*UDPClientPool, error) {
	if numPorts <= 0 {
		numPorts = 1
	}

	pool := &UDPClientPool{
		clients: make([]*UDPClient, 0, numPorts),
	}

	for i := 0; i < numPorts; i++ {
		port := smfPort + i
		client, err := NewUDPClient(smfAddr, port, upfAddr, upfPort)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to create UDP client on port %d: %w", port, err)
		}
		pool.clients = append(pool.clients, client)
	}

	return pool, nil
}

// NextPortIndex returns the next port index using round-robin.
func (p *UDPClientPool) NextPortIndex() int {
	return int(p.counter.Add(1)-1) % len(p.clients)
}

// Send sends data using round-robin port selection. Returns the port index used.
func (p *UDPClientPool) Send(data []byte) (int, error) {
	idx := p.NextPortIndex()
	return idx, p.clients[idx].Send(data)
}

// SendOn sends data on a specific port index (for retransmission on the same port).
func (p *UDPClientPool) SendOn(portIndex int, data []byte) error {
	if portIndex < 0 || portIndex >= len(p.clients) {
		portIndex = 0
	}
	return p.clients[portIndex].Send(data)
}

// Conns returns all UDP connections for receiver setup.
func (p *UDPClientPool) Conns() []*net.UDPConn {
	conns := make([]*net.UDPConn, len(p.clients))
	for i, c := range p.clients {
		conns[i] = c.Conn()
	}
	return conns
}

// Close closes all clients in the pool.
func (p *UDPClientPool) Close() error {
	var lastErr error
	for _, c := range p.clients {
		if c != nil {
			if err := c.Close(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// Size returns the number of ports in the pool.
func (p *UDPClientPool) Size() int {
	return len(p.clients)
}

// LocalAddrs returns all local addresses in the pool.
func (p *UDPClientPool) LocalAddrs() []net.Addr {
	addrs := make([]net.Addr, len(p.clients))
	for i, c := range p.clients {
		addrs[i] = c.LocalAddr()
	}
	return addrs
}
