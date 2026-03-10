package network

import (
	"context"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"
)

// ReceivedMessage represents a PFCP message received from the UPF.
type ReceivedMessage struct {
	Message message.Message
	Data    []byte
	From    *net.UDPAddr
}

// Receiver listens for PFCP responses from the UPF.
type Receiver struct {
	conn    *net.UDPConn
	msgChan chan ReceivedMessage
}

var bufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 65535) },
}

// NewReceiver creates a new receiver using the same UDP connection as the sender.
// bufSize sets the channel buffer capacity; use 0 for the default (1000).
func NewReceiver(conn *net.UDPConn, bufSize int) *Receiver {
	if bufSize <= 0 {
		bufSize = 1000
	}
	return &Receiver{
		conn:    conn,
		msgChan: make(chan ReceivedMessage, bufSize),
	}
}

// Start begins listening for incoming PFCP messages in a goroutine.
func (r *Receiver) Start(ctx context.Context) {
	go r.listen(ctx)
}

// Messages returns the channel of received messages.
func (r *Receiver) Messages() <-chan ReceivedMessage {
	return r.msgChan
}

func (r *Receiver) listen(ctx context.Context) {
	defer close(r.msgChan)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		buf := bufPool.Get().([]byte)
		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			bufPool.Put(buf)
			if ctx.Err() != nil {
				return // Context cancelled, normal shutdown
			}
			log.WithError(err).Warn("Error reading from UDP")
			continue
		}

		// Copy data out so we can return buffer to pool
		data := make([]byte, n)
		copy(data, buf[:n])
		bufPool.Put(buf)

		msg, err := message.Parse(data)
		if err != nil {
			log.WithError(err).WithField("from", addr).Warn("Failed to parse received PFCP message")
			continue
		}

		select {
		case r.msgChan <- ReceivedMessage{
			Message: msg,
			Data:    data,
			From:    addr,
		}:
		case <-ctx.Done():
			return
		}
	}
}
