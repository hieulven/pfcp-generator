package stats

import (
	"sort"
	"sync"
	"time"
)

// MessageTypeStats holds per-message-type statistics.
type MessageTypeStats struct {
	Sent       uint64
	Received   uint64
	Success    uint64
	Failed     uint64
	Timeout    uint64
	Retransmit uint64
}

// Collector aggregates operational statistics.
type Collector struct {
	StartTime time.Time
	EndTime   time.Time

	MessageStats map[string]*MessageTypeStats

	SessionsEstablished uint64
	SessionsModified    uint64
	SessionsDeleted     uint64
	SessionsFailed      uint64
	ActiveSessions      uint64

	ResponseTimes []time.Duration

	mu sync.Mutex
}

// NewCollector creates a new statistics collector.
func NewCollector() *Collector {
	return &Collector{
		StartTime:    time.Now(),
		MessageStats: make(map[string]*MessageTypeStats),
	}
}

func (c *Collector) getOrCreate(msgType string) *MessageTypeStats {
	if _, ok := c.MessageStats[msgType]; !ok {
		c.MessageStats[msgType] = &MessageTypeStats{}
	}
	return c.MessageStats[msgType]
}

// RecordSent records a message being sent.
func (c *Collector) RecordSent(msgType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getOrCreate(msgType).Sent++
}

// RecordReceived records a response being received.
func (c *Collector) RecordReceived(msgType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getOrCreate(msgType).Received++
}

// RecordSuccess records a successful transaction.
func (c *Collector) RecordSuccess(msgType string, responseTime time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getOrCreate(msgType).Success++
	c.ResponseTimes = append(c.ResponseTimes, responseTime)
}

// RecordFailure records a failed transaction (cause != accepted).
func (c *Collector) RecordFailure(msgType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getOrCreate(msgType).Failed++
}

// RecordTimeout records a transaction timeout.
func (c *Collector) RecordTimeout(msgType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getOrCreate(msgType).Timeout++
}

// RecordRetransmit records a retransmission.
func (c *Collector) RecordRetransmit(msgType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getOrCreate(msgType).Retransmit++
}

// RecordSessionEstablished increments established session count.
func (c *Collector) RecordSessionEstablished() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SessionsEstablished++
	c.ActiveSessions++
}

// RecordSessionModified increments modified session count.
func (c *Collector) RecordSessionModified() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SessionsModified++
}

// RecordSessionDeleted increments deleted session count.
func (c *Collector) RecordSessionDeleted() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SessionsDeleted++
	if c.ActiveSessions > 0 {
		c.ActiveSessions--
	}
}

// RecordSessionFailed increments failed session count.
func (c *Collector) RecordSessionFailed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SessionsFailed++
}

// Finish marks the end of the collection period.
func (c *Collector) Finish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.EndTime = time.Now()
}

// Duration returns the elapsed time.
func (c *Collector) Duration() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.EndTime.IsZero() {
		return time.Since(c.StartTime)
	}
	return c.EndTime.Sub(c.StartTime)
}

// TotalSent returns the total number of messages sent.
func (c *Collector) TotalSent() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var total uint64
	for _, s := range c.MessageStats {
		total += s.Sent
	}
	return total
}

// TotalReceived returns the total number of responses received.
func (c *Collector) TotalReceived() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var total uint64
	for _, s := range c.MessageStats {
		total += s.Received
	}
	return total
}

// ResponseTimeStats returns min, avg, max, and p99 response times.
func (c *Collector) ResponseTimeStats() (min, avg, max, p99 time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.ResponseTimes) == 0 {
		return 0, 0, 0, 0
	}

	sorted := make([]time.Duration, len(c.ResponseTimes))
	copy(sorted, c.ResponseTimes)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	min = sorted[0]
	max = sorted[len(sorted)-1]

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	avg = total / time.Duration(len(sorted))

	p99Idx := int(float64(len(sorted)) * 0.99)
	if p99Idx >= len(sorted) {
		p99Idx = len(sorted) - 1
	}
	p99 = sorted[p99Idx]

	return
}

// Snapshot returns a copy of the current statistics (thread-safe).
func (c *Collector) Snapshot() *Collector {
	c.mu.Lock()
	defer c.mu.Unlock()

	snap := &Collector{
		StartTime:           c.StartTime,
		EndTime:             c.EndTime,
		MessageStats:        make(map[string]*MessageTypeStats),
		SessionsEstablished: c.SessionsEstablished,
		SessionsModified:    c.SessionsModified,
		SessionsDeleted:     c.SessionsDeleted,
		SessionsFailed:      c.SessionsFailed,
		ActiveSessions:      c.ActiveSessions,
		ResponseTimes:       make([]time.Duration, len(c.ResponseTimes)),
	}
	copy(snap.ResponseTimes, c.ResponseTimes)

	for k, v := range c.MessageStats {
		snap.MessageStats[k] = &MessageTypeStats{
			Sent:       v.Sent,
			Received:   v.Received,
			Success:    v.Success,
			Failed:     v.Failed,
			Timeout:    v.Timeout,
			Retransmit: v.Retransmit,
		}
	}

	return snap
}
