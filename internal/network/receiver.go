package network

import (
	"context"
	"net"

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

// NewReceiver creates a new receiver using the same UDP connection as the sender.
func NewReceiver(conn *net.UDPConn) *Receiver {
	return &Receiver{
		conn:    conn,
		msgChan: make(chan ReceivedMessage, 1000),
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

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return // Context cancelled, normal shutdown
			}
			log.WithError(err).Warn("Error reading from UDP")
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

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
