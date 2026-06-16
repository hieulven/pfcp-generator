package network

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"pfcp-generator/pkg/types"
)

const numShards = 64

// RetransmitSender can send data on a specific port index (for retransmission).
type RetransmitSender interface {
	SendOn(portIndex int, data []byte) error
}

// PendingTransaction represents a request awaiting a response.
type PendingTransaction struct {
	SeqNum      uint32
	RequestData []byte
	PortIndex   int
	SentAt      time.Time
	RetryCount  int
	ResultCh    chan types.TransactionResult
	// Owner is the originating session for TrackWith registrations.
	Owner *types.SessionInfo
	// MsgType names the request type for stats propagation.
	MsgType string
	// SharedCh marks a shared channel: push is non-blocking (drop on full).
	SharedCh bool
}

type txShard struct {
	pending map[uint32]*PendingTransaction
	mu      sync.Mutex
}

// TransactionTracker manages pending PFCP transactions using sharded maps.
type TransactionTracker struct {
	shards     [numShards]txShard
	timeout    time.Duration
	maxRetries int
	sender     RetransmitSender
}

// NewTransactionTracker creates a new transaction tracker.
func NewTransactionTracker(sender RetransmitSender, timeoutMs int, maxRetries int) *TransactionTracker {
	t := &TransactionTracker{
		timeout:    time.Duration(timeoutMs) * time.Millisecond,
		maxRetries: maxRetries,
		sender:     sender,
	}
	for i := range t.shards {
		t.shards[i].pending = make(map[uint32]*PendingTransaction)
	}
	return t
}

func (t *TransactionTracker) shard(seqNum uint32) *txShard {
	return &t.shards[seqNum%numShards]
}

// Track registers a new pending transaction and returns a per-transaction result channel.
// portIndex identifies which source port was used (for retransmission on the same port).
func (t *TransactionTracker) Track(seqNum uint32, requestData []byte, portIndex int) <-chan types.TransactionResult {
	s := t.shard(seqNum)
	resultCh := make(chan types.TransactionResult, 1)

	s.mu.Lock()
	s.pending[seqNum] = &PendingTransaction{
		SeqNum:      seqNum,
		RequestData: requestData,
		PortIndex:   portIndex,
		SentAt:      time.Now(),
		ResultCh:    resultCh,
	}
	s.mu.Unlock()

	return resultCh
}

// TrackWith registers a pending transaction that resolves into a shared channel.
// owner is attached to the result so the collector needs no seq→session map.
// msgType names the request type for stats draining.
// The push to shared is non-blocking: drops are preferred over stalling handleResponses.
func (t *TransactionTracker) TrackWith(seqNum uint32, requestData []byte, portIndex int, owner *types.SessionInfo, msgType string, shared chan types.TransactionResult) {
	s := t.shard(seqNum)
	s.mu.Lock()
	s.pending[seqNum] = &PendingTransaction{
		SeqNum:      seqNum,
		RequestData: requestData,
		PortIndex:   portIndex,
		SentAt:      time.Now(),
		ResultCh:    shared,
		Owner:       owner,
		MsgType:     msgType,
		SharedCh:    true,
	}
	s.mu.Unlock()
}

// send pushes result to tx.ResultCh respecting the SharedCh flag.
func send(tx *PendingTransaction, result types.TransactionResult) {
	if tx.SharedCh {
		select {
		case tx.ResultCh <- result:
		default:
			// Drop under back-pressure — shared channels are generously buffered;
			// dropping is always preferable to stalling the response handler.
		}
	} else {
		tx.ResultCh <- result // buffered-1 per-tx channel, never stalls
	}
}

// Resolve matches a received response to a pending transaction.
func (t *TransactionTracker) Resolve(seqNum uint32, responseData []byte) {
	s := t.shard(seqNum)

	s.mu.Lock()
	tx, exists := s.pending[seqNum]
	if !exists {
		s.mu.Unlock()
		log.WithField("seq_num", seqNum).Warn("Received response for unknown transaction")
		return
	}
	delete(s.pending, seqNum)
	s.mu.Unlock()

	send(tx, types.TransactionResult{
		SeqNum:       seqNum,
		Response:     responseData,
		ResponseTime: time.Since(tx.SentAt),
		Owner:        tx.Owner,
		MsgType:      tx.MsgType,
	})
}

// StartTimeoutMonitor starts a goroutine that checks for timed-out transactions.
func (t *TransactionTracker) StartTimeoutMonitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.checkTimeouts()
			}
		}
	}()
}

func (t *TransactionTracker) checkTimeouts() {
	now := time.Now()
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		var timedOut []*PendingTransaction
		for _, tx := range s.pending {
			if now.Sub(tx.SentAt) > t.timeout {
				timedOut = append(timedOut, tx)
			}
		}
		s.mu.Unlock()

		for _, tx := range timedOut {
			t.handleTimeout(tx)
		}
	}
}

func (t *TransactionTracker) handleTimeout(tx *PendingTransaction) {
	s := t.shard(tx.SeqNum)
	s.mu.Lock()
	// Verify still pending (may have been resolved between check and handle)
	if _, exists := s.pending[tx.SeqNum]; !exists {
		s.mu.Unlock()
		return
	}

	if tx.RetryCount < t.maxRetries {
		tx.RetryCount++
		tx.SentAt = time.Now() // Reset timeout
		s.mu.Unlock()

		log.WithFields(log.Fields{
			"seq_num": tx.SeqNum,
			"attempt": tx.RetryCount,
			"max":     t.maxRetries,
		}).Warn("Transaction timeout, retransmitting")

		if err := t.sender.SendOn(tx.PortIndex, tx.RequestData); err != nil {
			log.WithError(err).WithField("seq_num", tx.SeqNum).Error("Retransmission failed")
		}
	} else {
		delete(s.pending, tx.SeqNum)
		s.mu.Unlock()

		log.WithFields(log.Fields{
			"seq_num": tx.SeqNum,
			"retries": t.maxRetries,
		}).Error("Transaction failed after max retries")

		send(tx, types.TransactionResult{
			SeqNum:  tx.SeqNum,
			Error:   fmt.Errorf("timeout after %d retries", t.maxRetries),
			Owner:   tx.Owner,
			MsgType: tx.MsgType,
		})
	}
}

// PendingCount returns the number of pending transactions across all shards.
func (t *TransactionTracker) PendingCount() int {
	total := 0
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		total += len(s.pending)
		s.mu.Unlock()
	}
	return total
}

// CancelAll cancels all pending transactions across all shards.
func (t *TransactionTracker) CancelAll() {
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for seqNum, tx := range s.pending {
			send(tx, types.TransactionResult{
				SeqNum:  seqNum,
				Error:   fmt.Errorf("cancelled"),
				Owner:   tx.Owner,
				MsgType: tx.MsgType,
			})
			delete(s.pending, seqNum)
		}
		s.mu.Unlock()
	}
}
