package stats

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Histogram bucket boundaries in nanoseconds.
// Fine resolution in the 1-10ms range where most PFCP responses land.
var histBoundaries = [...]int64{
	50_000,        // 50µs
	100_000,       // 100µs
	150_000,       // 150µs
	200_000,       // 200µs
	300_000,       // 300µs
	500_000,       // 500µs
	750_000,       // 750µs
	1_000_000,     // 1ms
	1_250_000,     // 1.25ms
	1_500_000,     // 1.5ms
	1_750_000,     // 1.75ms
	2_000_000,     // 2ms
	2_500_000,     // 2.5ms
	3_000_000,     // 3ms
	3_500_000,     // 3.5ms
	4_000_000,     // 4ms
	5_000_000,     // 5ms
	6_000_000,     // 6ms
	7_000_000,     // 7ms
	8_000_000,     // 8ms
	10_000_000,    // 10ms
	15_000_000,    // 15ms
	20_000_000,    // 20ms
	30_000_000,    // 30ms
	50_000_000,    // 50ms
	75_000_000,    // 75ms
	100_000_000,   // 100ms
	200_000_000,   // 200ms
	500_000_000,   // 500ms
	1_000_000_000, // 1s
	2_000_000_000, // 2s
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

// Sum returns the total of all observations in nanoseconds.
func (h *ResponseTimeHistogram) Sum() int64 {
	return h.sum.Load()
}

// CumulativeBuckets returns the upper bound (in nanoseconds) and cumulative
// observation count for each histogram bucket, in ascending order. The last
// bucket has no finite upper bound (it covers everything above the highest
// boundary) and is reported with bound math.MaxInt64.
func (h *ResponseTimeHistogram) CumulativeBuckets() (bounds []int64, cumulativeCounts []uint64) {
	bounds = make([]int64, numBuckets)
	cumulativeCounts = make([]uint64, numBuckets)
	var cumulative uint64
	for i := 0; i < numBuckets; i++ {
		cumulative += h.buckets[i].Load()
		cumulativeCounts[i] = cumulative
		if i < len(histBoundaries) {
			bounds[i] = histBoundaries[i]
		} else {
			bounds[i] = math.MaxInt64
		}
	}
	return bounds, cumulativeCounts
}

// percentile uses linear interpolation within the bucket that contains the
// target rank, producing smooth values instead of snapping to bucket boundaries.
func (h *ResponseTimeHistogram) percentile(total uint64, pct float64) time.Duration {
	target := float64(total) * pct
	if target < 1 {
		target = 1
	}

	var cumulative uint64
	for i := 0; i < numBuckets; i++ {
		bucketCount := h.buckets[i].Load()
		prevCumulative := cumulative
		cumulative += bucketCount
		if float64(cumulative) >= target && bucketCount > 0 {
			// Target rank falls within bucket i.
			// Bucket i covers the range (lowerBound, upperBound].
			var lowerBound, upperBound int64
			if i == 0 {
				lowerBound = 0
			} else {
				lowerBound = histBoundaries[i-1]
			}
			if i < len(histBoundaries) {
				upperBound = histBoundaries[i]
			} else {
				return time.Duration(h.max.Load())
			}

			// Interpolate: position within this bucket (0.0 = bottom, 1.0 = top)
			rankInBucket := target - float64(prevCumulative)
			fraction := rankInBucket / float64(bucketCount)
			interpolated := float64(lowerBound) + fraction*float64(upperBound-lowerBound)
			return time.Duration(int64(interpolated))
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