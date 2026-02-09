package network

import (
	"fmt"
	"net"
	"sync"
)

// UDPClient handles UDP communication with the UPF.
type UDPClient struct {
	conn    *net.UDPConn
	upfAddr *net.UDPAddr
	mu      sync.Mutex
}

// NewUDPClient creates a new UDP client bound to the SMF address and targeting the UPF.
func NewUDPClient(smfAddr string, smfPort int, upfAddr string, upfPort int) (*UDPClient, error) {
	localAddr := &net.UDPAddr{
		IP:   net.ParseIP(smfAddr),
		Port: smfPort,
	}

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upfAddr),
		Port: upfPort,
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind UDP to %s:%d: %w", smfAddr, smfPort, err)
	}

	return &UDPClient{
		conn:    conn,
		upfAddr: remoteAddr,
	}, nil
}

// Send transmits data to the UPF.
func (c *UDPClient) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.conn.WriteToUDP(data, c.upfAddr)
	if err != nil {
		return fmt.Errorf("failed to send to UPF %s: %w", c.upfAddr, err)
	}
	return nil
}

// Conn returns the underlying UDP connection (for the receiver to read from).
func (c *UDPClient) Conn() *net.UDPConn {
	return c.conn
}

// Close closes the UDP connection.
func (c *UDPClient) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local address the client is bound to.
func (c *UDPClient) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}
