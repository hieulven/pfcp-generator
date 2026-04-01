package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"
)

// extractSeqNum extracts the 24-bit sequence number from raw PFCP bytes.
// This avoids the full message.Parse which allocates and parses all IEs.
// PFCP header layout:
//
//	Without SEID (S=0): [flags(1)][type(1)][len(2)][seq(3)][spare(1)] = 8 bytes
//	With SEID (S=1):    [flags(1)][type(1)][len(2)][SEID(8)][seq(3)][spare(1)] = 16 bytes
func extractSeqNum(data []byte) (uint32, error) {
	if len(data) < 8 {
		return 0, fmt.Errorf("packet too short: %d bytes", len(data))
	}
	sFlag := data[0] & 0x01
	if sFlag != 0 {
		// SEID present: seq at offset 12
		if len(data) < 16 {
			return 0, fmt.Errorf("SEID packet too short: %d bytes", len(data))
		}
		return uint32(data[12])<<16 | uint32(data[13])<<8 | uint32(data[14]), nil
	}
	// No SEID: seq at offset 4
	return uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6]), nil
}

// isClosedError returns true if the error indicates a closed connection.
func isClosedError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Err.Error() == "use of closed network connection"
	}
	return false
}

// ReceivedMessage represents a PFCP message received from the UPF.
type ReceivedMessage struct {
	SeqNum uint32
	Data   []byte
	From   *net.UDPAddr
}

// Receiver listens for PFCP responses from the UPF.
type Receiver struct {
	conns   []*net.UDPConn
	msgChan chan ReceivedMessage
}

var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 65535) },
}

// NewReceiver creates a new receiver for a single UDP connection.
// bufSize sets the channel buffer capacity; use 0 for the default (1000).
func NewReceiver(conn *net.UDPConn, bufSize int) *Receiver {
	if bufSize <= 0 {
		bufSize = 1000
	}
	return &Receiver{
		conns:   []*net.UDPConn{conn},
		msgChan: make(chan ReceivedMessage, bufSize),
	}
}

// NewMultiReceiver creates a receiver that fans in from multiple UDP connections.
func NewMultiReceiver(conns []*net.UDPConn, bufSize int) *Receiver {
	if bufSize <= 0 {
		bufSize = 1000
	}
	return &Receiver{
		conns:   conns,
		msgChan: make(chan ReceivedMessage, bufSize),
	}
}

// Start begins listening for incoming PFCP messages in goroutines (one per connection).
func (r *Receiver) Start(ctx context.Context) {
	var wg sync.WaitGroup
	for _, conn := range r.conns {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			r.listenOn(ctx, c)
		}(conn)
	}
	go func() {
		wg.Wait()
		close(r.msgChan)
	}()
}

// Messages returns the channel of received messages.
func (r *Receiver) Messages() <-chan ReceivedMessage {
	return r.msgChan
}

func (r *Receiver) listenOn(ctx context.Context, conn *net.UDPConn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		buf := bufPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			bufPool.Put(buf)
			// Closed connection or cancelled context means normal shutdown
			if ctx.Err() != nil || isClosedError(err) {
				return
			}
			log.WithError(err).Warn("Error reading from UDP")
			continue
		}

		// Copy data out so we can return buffer to pool
		data := make([]byte, n)
		copy(data, buf[:n])
		bufPool.Put(buf)

		// Fast path: extract sequence number directly from raw bytes.
		// PFCP header: [version+flags(1)] [type(1)] [length(2)] [SEID(8)?] [seq(3)] [spare(1)]
		// S flag (bit 0 of byte 0) indicates SEID presence.
		seqNum, parseErr := extractSeqNum(data)
		if parseErr != nil {
			// Fallback to full parse for non-standard messages
			msg, err := message.Parse(data)
			if err != nil {
				log.WithError(err).WithField("from", addr).Warn("Failed to parse received PFCP message")
				continue
			}
			seqNum = msg.Sequence()
		}

		select {
		case r.msgChan <- ReceivedMessage{
			SeqNum: seqNum,
			Data:   data,
			From:   addr,
		}:
		case <-ctx.Done():
			return
		}
	}
}
