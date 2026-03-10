package network

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"

	"pfcp-generator/pkg/types"
)

const numShards = 64

// PendingTransaction represents a request awaiting a response.
type PendingTransaction struct {
	SeqNum      uint32
	RequestData []byte
	SentAt      time.Time
	RetryCount  int
	ResultCh    chan types.TransactionResult
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
	sender     *UDPClient
}

// NewTransactionTracker creates a new transaction tracker.
func NewTransactionTracker(sender *UDPClient, timeoutMs int, maxRetries int) *TransactionTracker {
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

// Track registers a new pending transaction and returns a channel for the result.
func (t *TransactionTracker) Track(seqNum uint32, requestData []byte) <-chan types.TransactionResult {
	s := t.shard(seqNum)
	resultCh := make(chan types.TransactionResult, 1)

	s.mu.Lock()
	s.pending[seqNum] = &PendingTransaction{
		SeqNum:      seqNum,
		RequestData: requestData,
		SentAt:      time.Now(),
		ResultCh:    resultCh,
	}
	s.mu.Unlock()

	return resultCh
}

// Resolve matches a received response to a pending transaction.
func (t *TransactionTracker) Resolve(seqNum uint32, response message.Message, responseData []byte) {
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

	responseTime := time.Since(tx.SentAt)
	tx.ResultCh <- types.TransactionResult{
		SeqNum:       seqNum,
		Response:     responseData,
		ResponseTime: responseTime,
	}
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

		if err := t.sender.Send(tx.RequestData); err != nil {
			log.WithError(err).WithField("seq_num", tx.SeqNum).Error("Retransmission failed")
		}
	} else {
		delete(s.pending, tx.SeqNum)
		s.mu.Unlock()

		log.WithFields(log.Fields{
			"seq_num": tx.SeqNum,
			"retries": t.maxRetries,
		}).Error("Transaction failed after max retries")

		tx.ResultCh <- types.TransactionResult{
			SeqNum: tx.SeqNum,
			Error:  fmt.Errorf("timeout after %d retries", t.maxRetries),
		}
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
			tx.ResultCh <- types.TransactionResult{
				SeqNum: seqNum,
				Error:  fmt.Errorf("cancelled"),
			}
			delete(s.pending, seqNum)
		}
		s.mu.Unlock()
	}
}
