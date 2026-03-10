package stats

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Histogram bucket boundaries in nanoseconds.
var histBoundaries = [...]int64{
	100_000,       // 100µs
	200_000,       // 200µs
	500_000,       // 500µs
	1_000_000,     // 1ms
	2_000_000,     // 2ms
	5_000_000,     // 5ms
	10_000_000,    // 10ms
	20_000_000,    // 20ms
	50_000_000,    // 50ms
	100_000_000,   // 100ms
	500_000_000,   // 500ms
	1_000_000_000, // 1s
	5_000_000_000, // 5s
}

const numBuckets = len(histBoundaries) + 1 // last bucket = >5s

// ResponseTimeHistogram tracks response time distribution with fixed memory.
type ResponseTimeHistogram struct {
	buckets [numBuckets]atomic.Uint64
	count   atomic.Uint64
	sum     atomic.Int64 // nanoseconds
	min     atomic.Int64
	max     atomic.Int64
}

// NewResponseTimeHistogram creates a new histogram.
func NewResponseTimeHistogram() *ResponseTimeHistogram {
	h := &ResponseTimeHistogram{}
	h.min.Store(math.MaxInt64)
	h.max.Store(0)
	return h
}

// Record adds a response time observation.
func (h *ResponseTimeHistogram) Record(d time.Duration) {
	ns := d.Nanoseconds()
	h.count.Add(1)
	h.sum.Add(ns)

	// Update min
	for {
		cur := h.min.Load()
		if ns >= cur || h.min.CompareAndSwap(cur, ns) {
			break
		}
	}
	// Update max
	for {
		cur := h.max.Load()
		if ns <= cur || h.max.CompareAndSwap(cur, ns) {
			break
		}
	}

	// Find bucket
	idx := len(histBoundaries) // default: last bucket (>5s)
	for i, bound := range histBoundaries {
		if ns <= bound {
			idx = i
			break
		}
	}
	h.buckets[idx].Add(1)
}

// Stats returns min, avg, max, p50, p95, p99.
func (h *ResponseTimeHistogram) Stats() (min, avg, max, p50, p95, p99 time.Duration) {
	count := h.count.Load()
	if count == 0 {
		return 0, 0, 0, 0, 0, 0
	}

	minNs := h.min.Load()
	if minNs == math.MaxInt64 {
		minNs = 0
	}
	min = time.Duration(minNs)
	max = time.Duration(h.max.Load())
	avg = time.Duration(h.sum.Load() / int64(count))

	p50 = h.percentile(count, 0.50)
	p95 = h.percentile(count, 0.95)
	p99 = h.percentile(count, 0.99)
	return
}

// Count returns the total number of observations.
func (h *ResponseTimeHistogram) Count() uint64 {
	return h.count.Load()
}

func (h *ResponseTimeHistogram) percentile(total uint64, pct float64) time.Duration {
	target := uint64(float64(total)*pct + 0.5)
	if target == 0 {
		target = 1
	}
	var cumulative uint64
	for i := 0; i < numBuckets; i++ {
		cumulative += h.buckets[i].Load()
		if cumulative >= target {
			// Return the upper bound of this bucket as the percentile estimate
			if i < len(histBoundaries) {
				return time.Duration(histBoundaries[i])
			}
			// Last bucket: return max
			return time.Duration(h.max.Load())
		}
	}
	return time.Duration(h.max.Load())
}

// MessageTypeStats holds per-message-type statistics using atomic counters.
type MessageTypeStats struct {
	Sent       atomic.Uint64
	Received   atomic.Uint64
	Success    atomic.Uint64
	Failed     atomic.Uint64
	Timeout    atomic.Uint64
	Retransmit atomic.Uint64
}

// MessageTypeStatsSnapshot is a plain copy for reporting.
type MessageTypeStatsSnapshot struct {
	Sent       uint64
	Received   uint64
	Success    uint64
	Failed     uint64
	Timeout    uint64
	Retransmit uint64
}

func (s *MessageTypeStats) snapshot() MessageTypeStatsSnapshot {
	return MessageTypeStatsSnapshot{
		Sent:       s.Sent.Load(),
		Received:   s.Received.Load(),
		Success:    s.Success.Load(),
		Failed:     s.Failed.Load(),
		Timeout:    s.Timeout.Load(),
		Retransmit: s.Retransmit.Load(),
	}
}

// Collector aggregates operational statistics using lock-free atomics.
type Collector struct {
	StartTime time.Time
	EndTime   time.Time

	// Pre-registered message type stats (sync.Map for dynamic registration)
	messageStats sync.Map // string → *MessageTypeStats

	SessionsEstablished atomic.Uint64
	SessionsModified    atomic.Uint64
	SessionsDeleted     atomic.Uint64
	SessionsFailed      atomic.Uint64
	ActiveSessions      atomic.Int64

	ResponseTimes *ResponseTimeHistogram

	mu sync.Mutex // only for EndTime
}

// NewCollector creates a new statistics collector.
func NewCollector() *Collector {
	return &Collector{
		StartTime:     time.Now(),
		ResponseTimes: NewResponseTimeHistogram(),
	}
}

func (c *Collector) getOrCreate(msgType string) *MessageTypeStats {
	if v, ok := c.messageStats.Load(msgType); ok {
		return v.(*MessageTypeStats)
	}
	s := &MessageTypeStats{}
	actual, _ := c.messageStats.LoadOrStore(msgType, s)
	return actual.(*MessageTypeStats)
}

// RecordSent records a message being sent.
func (c *Collector) RecordSent(msgType string) {
	c.getOrCreate(msgType).Sent.Add(1)
}

// RecordReceived records a response being received.
func (c *Collector) RecordReceived(msgType string) {
	c.getOrCreate(msgType).Received.Add(1)
}

// RecordSuccess records a successful transaction.
func (c *Collector) RecordSuccess(msgType string, responseTime time.Duration) {
	c.getOrCreate(msgType).Success.Add(1)
	c.ResponseTimes.Record(responseTime)
}

// RecordFailure records a failed transaction (cause != accepted).
func (c *Collector) RecordFailure(msgType string) {
	c.getOrCreate(msgType).Failed.Add(1)
}

// RecordTimeout records a transaction timeout.
func (c *Collector) RecordTimeout(msgType string) {
	c.getOrCreate(msgType).Timeout.Add(1)
}

// RecordRetransmit records a retransmission.
func (c *Collector) RecordRetransmit(msgType string) {
	c.getOrCreate(msgType).Retransmit.Add(1)
}

// RecordSessionEstablished increments established session count.
func (c *Collector) RecordSessionEstablished() {
	c.SessionsEstablished.Add(1)
	c.ActiveSessions.Add(1)
}

// RecordSessionModified increments modified session count.
func (c *Collector) RecordSessionModified() {
	c.SessionsModified.Add(1)
}

// RecordSessionDeleted increments deleted session count.
func (c *Collector) RecordSessionDeleted() {
	c.SessionsDeleted.Add(1)
	c.ActiveSessions.Add(-1)
}

// RecordSessionFailed increments failed session count.
func (c *Collector) RecordSessionFailed() {
	c.SessionsFailed.Add(1)
}

// Finish marks the end of the collection period.
func (c *Collector) Finish() {
	c.mu.Lock()
	c.EndTime = time.Now()
	c.mu.Unlock()
}

// Duration returns the elapsed time.
func (c *Collector) Duration() time.Duration {
	c.mu.Lock()
	endTime := c.EndTime
	c.mu.Unlock()
	if endTime.IsZero() {
		return time.Since(c.StartTime)
	}
	return endTime.Sub(c.StartTime)
}

// TotalSent returns the total number of messages sent.
func (c *Collector) TotalSent() uint64 {
	var total uint64
	c.messageStats.Range(func(_, v interface{}) bool {
		total += v.(*MessageTypeStats).Sent.Load()
		return true
	})
	return total
}

// TotalReceived returns the total number of responses received.
func (c *Collector) TotalReceived() uint64 {
	var total uint64
	c.messageStats.Range(func(_, v interface{}) bool {
		total += v.(*MessageTypeStats).Received.Load()
		return true
	})
	return total
}

// ResponseTimeStats returns min, avg, max, and p99 response times.
func (c *Collector) ResponseTimeStats() (min, avg, max, p99 time.Duration) {
	minV, avgV, maxV, _, _, p99V := c.ResponseTimes.Stats()
	return minV, avgV, maxV, p99V
}

// CollectorSnapshot is a point-in-time copy of collector state for reporting.
type CollectorSnapshot struct {
	StartTime           time.Time
	EndTime             time.Time
	MessageStats        map[string]MessageTypeStatsSnapshot
	SessionsEstablished uint64
	SessionsModified    uint64
	SessionsDeleted     uint64
	SessionsFailed      uint64
	ActiveSessions      int64
	RespMin             time.Duration
	RespAvg             time.Duration
	RespMax             time.Duration
	RespP50             time.Duration
	RespP95             time.Duration
	RespP99             time.Duration
	RespCount           uint64
}

// Snapshot returns a point-in-time copy of the statistics.
func (c *Collector) Snapshot() *CollectorSnapshot {
	c.mu.Lock()
	endTime := c.EndTime
	c.mu.Unlock()

	snap := &CollectorSnapshot{
		StartTime:           c.StartTime,
		EndTime:             endTime,
		MessageStats:        make(map[string]MessageTypeStatsSnapshot),
		SessionsEstablished: c.SessionsEstablished.Load(),
		SessionsModified:    c.SessionsModified.Load(),
		SessionsDeleted:     c.SessionsDeleted.Load(),
		SessionsFailed:      c.SessionsFailed.Load(),
		ActiveSessions:      c.ActiveSessions.Load(),
		RespCount:           c.ResponseTimes.Count(),
	}

	snap.RespMin, snap.RespAvg, snap.RespMax, snap.RespP50, snap.RespP95, snap.RespP99 = c.ResponseTimes.Stats()

	c.messageStats.Range(func(k, v interface{}) bool {
		snap.MessageStats[k.(string)] = v.(*MessageTypeStats).snapshot()
		return true
	})

	return snap
}

// SnapshotDuration returns the duration for a snapshot.
func (s *CollectorSnapshot) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// TotalSent returns total sent from a snapshot.
func (s *CollectorSnapshot) TotalSent() uint64 {
	var total uint64
	for _, ms := range s.MessageStats {
		total += ms.Sent
	}
	return total
}
