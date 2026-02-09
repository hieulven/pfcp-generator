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

// PendingTransaction represents a request awaiting a response.
type PendingTransaction struct {
	SeqNum      uint32
	RequestData []byte
	SentAt      time.Time
	RetryCount  int
	ResultCh    chan types.TransactionResult
}

// TransactionTracker manages pending PFCP transactions.
type TransactionTracker struct {
	pending    map[uint32]*PendingTransaction
	mu         sync.Mutex
	timeout    time.Duration
	maxRetries int
	sender     *UDPClient
}

// NewTransactionTracker creates a new transaction tracker.
func NewTransactionTracker(sender *UDPClient, timeoutMs int, maxRetries int) *TransactionTracker {
	return &TransactionTracker{
		pending:    make(map[uint32]*PendingTransaction),
		timeout:    time.Duration(timeoutMs) * time.Millisecond,
		maxRetries: maxRetries,
		sender:     sender,
	}
}

// Track registers a new pending transaction and returns a channel for the result.
func (t *TransactionTracker) Track(seqNum uint32, requestData []byte) <-chan types.TransactionResult {
	t.mu.Lock()
	defer t.mu.Unlock()

	resultCh := make(chan types.TransactionResult, 1)
	t.pending[seqNum] = &PendingTransaction{
		SeqNum:      seqNum,
		RequestData: requestData,
		SentAt:      time.Now(),
		ResultCh:    resultCh,
	}

	return resultCh
}

// Resolve matches a received response to a pending transaction.
func (t *TransactionTracker) Resolve(seqNum uint32, response message.Message, responseData []byte) {
	t.mu.Lock()
	tx, exists := t.pending[seqNum]
	if !exists {
		t.mu.Unlock()
		log.WithField("seq_num", seqNum).Warn("Received response for unknown transaction")
		return
	}
	delete(t.pending, seqNum)
	t.mu.Unlock()

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
	t.mu.Lock()
	var timedOut []*PendingTransaction
	now := time.Now()

	for _, tx := range t.pending {
		if now.Sub(tx.SentAt) > t.timeout {
			timedOut = append(timedOut, tx)
		}
	}
	t.mu.Unlock()

	for _, tx := range timedOut {
		t.handleTimeout(tx)
	}
}

func (t *TransactionTracker) handleTimeout(tx *PendingTransaction) {
	t.mu.Lock()
	// Verify still pending (may have been resolved between check and handle)
	if _, exists := t.pending[tx.SeqNum]; !exists {
		t.mu.Unlock()
		return
	}

	if tx.RetryCount < t.maxRetries {
		tx.RetryCount++
		tx.SentAt = time.Now() // Reset timeout
		t.mu.Unlock()

		log.WithFields(log.Fields{
			"seq_num": tx.SeqNum,
			"attempt": tx.RetryCount,
			"max":     t.maxRetries,
		}).Warn("Transaction timeout, retransmitting")

		if err := t.sender.Send(tx.RequestData); err != nil {
			log.WithError(err).WithField("seq_num", tx.SeqNum).Error("Retransmission failed")
		}
	} else {
		delete(t.pending, tx.SeqNum)
		t.mu.Unlock()

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

// PendingCount returns the number of pending transactions.
func (t *TransactionTracker) PendingCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending)
}

// CancelAll cancels all pending transactions.
func (t *TransactionTracker) CancelAll() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for seqNum, tx := range t.pending {
		tx.ResultCh <- types.TransactionResult{
			SeqNum: seqNum,
			Error:  fmt.Errorf("cancelled"),
		}
		delete(t.pending, seqNum)
	}
}
