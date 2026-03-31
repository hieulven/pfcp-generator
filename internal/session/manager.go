package session

import (
	"container/heap"
	"context"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"pfcp-generator/internal/config"
	"pfcp-generator/internal/network"
	"pfcp-generator/internal/pfcp"
	"pfcp-generator/internal/stats"
	"pfcp-generator/pkg/types"
)

// pendingSession is a session that has completed its lifecycle messages and is
// waiting for its adaptive delay to expire before deletion is sent.
type pendingSession struct {
	session  *types.SessionInfo
	deleteAt time.Time
}

// pendingHeap is a min-heap of pendingSession ordered by deleteAt.
type pendingHeap []pendingSession

func (h pendingHeap) Len() int            { return len(h) }
func (h pendingHeap) Less(i, j int) bool  { return h[i].deleteAt.Before(h[j].deleteAt) }
func (h pendingHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *pendingHeap) Push(x interface{}) { *h = append(*h, x.(pendingSession)) }
func (h *pendingHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// Manager orchestrates the PFCP session replay workflow.
type Manager struct {
	cfg        *config.Config
	pool       *network.UDPClientPool
	receiver   *network.Receiver
	tracker    *network.TransactionTracker
	modifier   *pfcp.Modifier
	seidAlloc  *SEIDAllocator
	ipPool     IPAllocator
	stats      *stats.Collector
	seqCounter *SequenceCounter

	// Session mappings
	byOriginalCPSEID     map[uint64]*types.SessionInfo
	byOriginalRemoteSEID map[uint64]*types.SessionInfo
	byLocalSEID          map[uint64]*types.SessionInfo
	mu                   sync.RWMutex

	// Original SEID mappings from pcap (CP SEID → remote SEID)
	originalSEIDMappings map[uint64]uint64
}

// SequenceCounter manages PFCP sequence numbers.
type SequenceCounter struct {
	current atomic.Uint32
}

// Next returns the next sequence number (24-bit, wraps at 0xFFFFFF).
func (s *SequenceCounter) Next() uint32 {
	for {
		cur := s.current.Add(1)
		val := cur & 0xFFFFFF
		if val == 0 {
			// Wrapped to 0, skip to 1
			continue
		}
		return val
	}
}

// NewManager creates a new session manager.
func NewManager(
	cfg *config.Config,
	pool *network.UDPClientPool,
	receiver *network.Receiver,
	tracker *network.TransactionTracker,
	statsCollector *stats.Collector,
) (*Manager, error) {
	smfIP := net.ParseIP(cfg.SMF.Address)
	seidAlloc := NewSEIDAllocator(cfg.Session.SEIDStrategy, cfg.Session.SEIDStart)

	pools := cfg.Session.AllPools()
	var ipPool IPAllocator
	if len(pools) == 1 {
		p, err := NewUEIPPool(pools[0])
		if err != nil {
			return nil, fmt.Errorf("failed to create UE IP pool: %w", err)
		}
		ipPool = p
	} else {
		p, err := NewMultiUEIPPool(pools)
		if err != nil {
			return nil, fmt.Errorf("failed to create UE IP pools: %w", err)
		}
		ipPool = p
	}

	modifier := pfcp.NewModifier(smfIP, cfg.Session.StripIPv6, cfg.Session.StripVendorIEs)

	return &Manager{
		cfg:                   cfg,
		pool:                  pool,
		receiver:              receiver,
		tracker:               tracker,
		modifier:              modifier,
		seidAlloc:             seidAlloc,
		ipPool:                ipPool,
		stats:                 statsCollector,
		seqCounter:            &SequenceCounter{},
		byOriginalCPSEID:     make(map[uint64]*types.SessionInfo),
		byOriginalRemoteSEID: make(map[uint64]*types.SessionInfo),
		byLocalSEID:          make(map[uint64]*types.SessionInfo),
		originalSEIDMappings: make(map[uint64]uint64),
	}, nil
}

// SetSEIDMappings registers the original CP SEID → remote SEID mappings
// extracted from Session Establishment Response messages in the pcap.
func (m *Manager) SetSEIDMappings(mappings []types.SEIDMapping) {
	for _, mapping := range mappings {
		m.originalSEIDMappings[mapping.OriginalCPSEID] = mapping.OriginalRemoteSEID
		log.WithFields(log.Fields{
			"cp_seid":     mapping.OriginalCPSEID,
			"remote_seid": mapping.OriginalRemoteSEID,
		}).Debug("Registered original SEID mapping from pcap")
	}
}

// StartResponseHandler starts the goroutine that dispatches UPF responses to pending transactions.
// Call this once before the first Replay call; it lives for the lifetime of ctx.
func (m *Manager) StartResponseHandler(ctx context.Context) {
	go m.handleResponses(ctx)
}

// Reset clears all session state so the manager can be reused for another replay iteration.
// It releases any resources still held by sessions that were not explicitly deleted.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, s := range m.byLocalSEID {
		m.seidAlloc.Release(s.LocalSEID)
		if s.UEIP != nil {
			m.ipPool.Release(s.UEIP)
		}
	}

	m.byOriginalCPSEID = make(map[uint64]*types.SessionInfo)
	m.byOriginalRemoteSEID = make(map[uint64]*types.SessionInfo)
	m.byLocalSEID = make(map[uint64]*types.SessionInfo)
}

// Replay processes all PFCP messages from the pcap in order (sequential mode).
func (m *Manager) Replay(ctx context.Context, messages []types.RawPFCPMessage) error {
	interval := time.Duration(m.cfg.Timing.MessageIntervalMs) * time.Millisecond

	for i, raw := range messages {
		select {
		case <-ctx.Done():
			log.Info("Replay cancelled")
			return ctx.Err()
		default:
		}

		msg, err := pfcp.Decode(raw.Data)
		if err != nil {
			log.WithError(err).WithField("index", i).Warn("Failed to decode PFCP message, skipping")
			continue
		}

		if err := m.processMessage(ctx, msg, raw); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"index":    i,
				"msg_type": pfcp.MessageTypeName(msg.MessageType()),
			}).Error("Failed to process message")
		}

		// Apply inter-message delay
		if interval > 0 && i < len(messages)-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
	}

	return nil
}

// adaptiveDelay manages the pre-deletion delay to keep active sessions at target.
type adaptiveDelay struct {
	delayNs atomic.Int64
}

func (d *adaptiveDelay) Get() time.Duration {
	return time.Duration(d.delayNs.Load())
}

func (d *adaptiveDelay) Set(v time.Duration) {
	d.delayNs.Store(int64(v))
}

// ReplayStress runs a high-performance stress test using the given replay plan.
//
// Each worker runs full session lifecycles from the pcap: Est → Mods → delay → Del.
// A semaphore caps concurrent active sessions at activeSessions.
// An adaptive delay before deletion keeps the active session count at the target.
// The delay also reduces goroutine contention on the rate limiter channel, improving TPS.
func (m *Manager) ReplayStress(ctx context.Context, plan *ReplayPlan, tps float64, activeSessions int, duration time.Duration) error {
	// Send association setup once if present
	if plan.AssociationSetup != nil && m.cfg.Association.Enabled {
		msg, err := pfcp.Decode(plan.AssociationSetup.Data)
		if err != nil {
			return fmt.Errorf("failed to decode association setup: %w", err)
		}
		if err := m.handleAssociationSetup(ctx, msg); err != nil {
			return fmt.Errorf("association setup failed: %w", err)
		}
	}

	// Create rate limiter
	rateLimiter := NewRateLimiter(ctx, tps)
	defer rateLimiter.Stop()

	// Timer for test duration
	var testCtx context.Context
	var testCancel context.CancelFunc
	if duration > 0 {
		testCtx, testCancel = context.WithTimeout(ctx, duration)
	} else {
		testCtx, testCancel = context.WithCancel(ctx)
	}
	defer testCancel()

	// Pre-encode all templates once at startup (Change 3).
	// Workers use byte-copy + field patching instead of decode→modify→encode per session.
	preEncoded := BuildPreEncodedTemplates(plan.Templates, m.modifier)
	if len(preEncoded) == 0 {
		return fmt.Errorf("no templates could be pre-encoded")
	}
	log.WithField("templates", len(preEncoded)).Info("Pre-encoded session templates")

	// Session semaphore: limits concurrent active sessions.
	// Released by the deletion dispatcher (not by workers) so it remains held
	// for the full session lifetime: establish → modifications → delay → delete.
	sem := make(chan struct{}, activeSessions)

	// pendingCh carries sessions that have finished their lifecycle messages and
	// are waiting for the adaptive delay before deletion. The deletion dispatcher
	// manages the timer-heap and fires deletions without holding worker goroutines.
	pendingCh := make(chan pendingSession, activeSessions)

	// Work channel: just a template index.
	workCh := make(chan int, activeSessions)

	// Adaptive delay: starts at 0, calibrated after warmup
	delay := &adaptiveDelay{}

	log.WithFields(log.Fields{
		"msgs_per_session": plan.MessagesPerSession,
	}).Info("Stress test starting")

	var completedSessions atomic.Uint64
	var failedSessions atomic.Uint64

	// Calibrator goroutine: adjusts delay after warmup to keep active sessions at target
	go func() {
		// Warmup: let sessions fill up before calibrating
		select {
		case <-testCtx.Done():
			return
		case <-time.After(10 * time.Second):
		}

		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-testCtx.Done():
				return
			case <-ticker.C:
				actual := int(m.stats.ActiveSessions.Load())
				target := activeSessions
				current := delay.Get()
				errorRatio := float64(target-actual) / float64(target)

				// Dead band: ±5% — don't adjust for small fluctuations
				if errorRatio > -0.05 && errorRatio < 0.05 {
					continue
				}

				// Proportional + additive adjustment (conservative gains)
				propAdj := time.Duration(float64(current) * errorRatio * 0.2)
				addAdj := time.Duration(float64(20*time.Millisecond) * errorRatio)
				adjustment := propAdj + addAdj

				maxAdj := 200 * time.Millisecond
				if adjustment > maxAdj {
					adjustment = maxAdj
				} else if adjustment < -maxAdj {
					adjustment = -maxAdj
				}

				newDelay := current + adjustment
				if newDelay < 0 {
					newDelay = 0
				}
				delay.Set(newDelay)

				log.WithFields(log.Fields{
					"active":   actual,
					"target":   target,
					"delay_ms": newDelay.Milliseconds(),
				}).Debug("Adaptive delay calibration")
			}
		}
	}()

	// Periodic progress logging
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-testCtx.Done():
				return
			case <-ticker.C:
				elapsed := m.stats.Duration()
				totalSent := m.stats.TotalSent()
				currentTPS := float64(0)
				if elapsed.Seconds() > 0 {
					currentTPS = float64(totalSent) / elapsed.Seconds()
				}
				log.WithFields(log.Fields{
					"completed":   completedSessions.Load(),
					"failed":      failedSessions.Load(),
					"active":      m.stats.ActiveSessions.Load(),
					"total_sent":  totalSent,
					"delay_ms":    delay.Get().Milliseconds(),
					"current_tps": fmt.Sprintf("%.0f", currentTPS),
					"target_tps":  fmt.Sprintf("%.0f", tps),
					"elapsed":     elapsed.Round(time.Second),
				}).Info("Stress test progress")
			}
		}
	}()

	// Deletion dispatcher (Change 2): one goroutine manages a min-heap of sessions
	// ordered by deletion time. When a session is due, it spawns a short-lived
	// goroutine to send the deletion and release the semaphore. This replaces the
	// previous design where each worker goroutine slept for the adaptive delay,
	// causing up to 10K sleeping goroutines to consume scheduler slots.
	go m.runDeletionDispatcher(testCtx, pendingCh, sem, rateLimiter, &failedSessions)

	// Feeder goroutine: acquires a semaphore slot then queues a template index.
	// Semaphore is released by the deletion dispatcher after deletion completes.
	go func() {
		defer close(workCh)
		templateCount := len(preEncoded)
		idx := 0
		for {
			select {
			case <-testCtx.Done():
				return
			case sem <- struct{}{}: // Acquire semaphore slot
				select {
				case workCh <- idx % templateCount:
					idx++
				case <-testCtx.Done():
					<-sem
					return
				}
			}
		}
	}()

	// Change 1: Use runtime.NumCPU()*4 workers instead of activeSessions.
	// The semaphore still caps active sessions at the target; fewer goroutines
	// means drastically less scheduler pressure. Workers spend their time doing
	// real work (network I/O) rather than sleeping for the adaptive delay.
	numWorkers := runtime.NumCPU() * 4
	if numWorkers < 16 {
		numWorkers = 16
	}
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go func() {
			defer wg.Done()
			for tmplIdx := range workCh {
				tmpl := &preEncoded[tmplIdx]
				err := m.executeStressSession(testCtx, tmpl, rateLimiter, delay, pendingCh)
				if err != nil {
					if testCtx.Err() != nil {
						// Context cancelled: release semaphore since dispatcher won't see this session.
						<-sem
						return
					}
					failedSessions.Add(1)
					log.WithError(err).Debug("Session failed")
					<-sem // Release semaphore on error (deletion dispatcher won't be called)
				} else {
					completedSessions.Add(1)
					// Semaphore is released by the deletion dispatcher, not here.
				}
			}
		}()
	}

	wg.Wait()

	log.WithFields(log.Fields{
		"completed":      completedSessions.Load(),
		"failed":         failedSessions.Load(),
		"final_delay_ms": delay.Get().Milliseconds(),
	}).Info("Stress test completed")

	return nil
}

// runDeletionDispatcher manages deferred session deletions using a min-heap.
// Sessions arrive via pendingCh with a target deleteAt time. The dispatcher
// wakes up when the earliest session is due, then spawns a short goroutine to
// send the deletion and release the semaphore. This reduces O(activeSessions)
// sleeping goroutines to O(1) goroutine + a heap, dramatically cutting scheduler load.
func (m *Manager) runDeletionDispatcher(
	ctx context.Context,
	pendingCh <-chan pendingSession,
	sem chan struct{},
	rateLimiter *RateLimiter,
	failedSessions *atomic.Uint64,
) {
	h := &pendingHeap{}
	heap.Init(h)

	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	var timerArmed bool

	armTimer := func(d time.Duration) {
		if timerArmed {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		if d < 0 {
			d = 0
		}
		timer.Reset(d)
		timerArmed = true
	}

	for {
		select {
		case <-ctx.Done():
			// Drain remaining sessions: release semaphore slots without sending deletion.
			for h.Len() > 0 {
				heap.Pop(h)
				<-sem
			}
			return

		case pd, ok := <-pendingCh:
			if !ok {
				return
			}
			heap.Push(h, pd)
			// Re-arm timer for the earliest due session.
			armTimer(time.Until((*h)[0].deleteAt))

		case <-timer.C:
			timerArmed = false
			now := time.Now()
			for h.Len() > 0 && !(*h)[0].deleteAt.After(now) {
				pd := heap.Pop(h).(pendingSession)
				// Short-lived deletion goroutine: does real network I/O then releases semaphore.
				// At 10K TPS with ~1ms RTT there are only ~10 of these in flight at steady state.
				go func(s *types.SessionInfo) {
					defer func() { <-sem }()
					if err := rateLimiter.Wait(ctx); err != nil {
						m.releaseSession(s)
						return
					}
					if err := m.sendSessionDeletion(ctx, s); err != nil && ctx.Err() == nil {
						failedSessions.Add(1)
						m.releaseSession(s)
					}
				}(pd.session)
			}
			// Re-arm for next due session, if any.
			if h.Len() > 0 {
				armTimer(time.Until((*h)[0].deleteAt))
			}
		}
	}
}

// executeStressSession runs a session lifecycle using pre-encoded byte templates:
// Est → Mods → push to pendingCh (for deferred deletion by dispatcher).
// Workers return immediately after pushing to pendingCh; the adaptive delay is
// handled by the deletion dispatcher's timer-heap, not by the worker goroutine.
func (m *Manager) executeStressSession(
	ctx context.Context,
	tmpl *PreEncodedTemplate,
	rateLimiter *RateLimiter,
	delay *adaptiveDelay,
	pendingCh chan<- pendingSession,
) error {
	// 1. Establish
	if err := rateLimiter.Wait(ctx); err != nil {
		return err
	}
	session, err := m.establishFromPreEncoded(ctx, tmpl.EstMsg)
	if err != nil {
		return err
	}

	// 2. Send modifications using pre-encoded byte templates (Change 3).
	for _, modMsg := range tmpl.ModMsgs {
		if err := rateLimiter.Wait(ctx); err != nil {
			m.cleanupStressSession(ctx, session)
			return err
		}
		if err := m.sendPreEncodedModification(ctx, modMsg, session); err != nil {
			if ctx.Err() != nil {
				m.cleanupStressSession(ctx, session)
				return err
			}
			log.WithError(err).Debug("Modification failed")
		}
	}

	// 3. Push to deletion dispatcher with jittered delay.
	// Worker returns immediately; deletion happens asynchronously.
	d := delay.Get()
	deleteAt := time.Now()
	if d > 0 {
		deleteAt = deleteAt.Add(time.Duration(float64(d) * (0.5 + rand.Float64())))
	}
	select {
	case pendingCh <- pendingSession{session: session, deleteAt: deleteAt}:
		return nil
	case <-ctx.Done():
		m.cleanupStressSession(ctx, session)
		return ctx.Err()
	}
}

// establishFromPreEncoded sends a pre-encoded Session Establishment Request,
// patches per-session fields (localSEID, UE IP, seq) by byte-copying the template,
// and waits for the UPF response to extract the remote SEID.
func (m *Manager) establishFromPreEncoded(ctx context.Context, pre *pfcp.PreEncodedMsg) (*types.SessionInfo, error) {
	localSEID, err := m.seidAlloc.Allocate()
	if err != nil {
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to allocate SEID: %w", err)
	}

	ueIP, err := m.ipPool.Allocate()
	if err != nil {
		m.seidAlloc.Release(localSEID)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to allocate UE IP: %w", err)
	}

	session := &types.SessionInfo{
		LocalSEID: localSEID,
		UEIP:      ueIP,
		State:     "establishing",
		CreatedAt: time.Now(),
	}

	m.mu.Lock()
	m.byLocalSEID[localSEID] = session
	m.mu.Unlock()

	seqNum := m.seqCounter.Next()

	// Byte-copy template and patch per-session fields. No PFCP decode/encode needed.
	data := make([]byte, len(pre.Data))
	pre.ApplyInto(data, seqNum, 0 /* header SEID=0 for establishment */, localSEID /* CP-FSEID SEID */, ueIP)

	msgTypeName := "SessionEstablishmentRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return nil, fmt.Errorf("failed to send Session Establishment: %w", err)
	}

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		m.stats.RecordSessionFailed()
		session.State = "failed"
		return nil, fmt.Errorf("Session Establishment timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionEstablishmentResponse")

	// Parse response to extract the UPF-assigned remote SEID.
	respMsg, err := pfcp.Decode(result.Response)
	if err != nil {
		m.stats.RecordFailure(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to decode Establishment Response: %w", err)
	}

	resp, ok := respMsg.(*message.SessionEstablishmentResponse)
	if !ok {
		m.stats.RecordFailure(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("unexpected response type: %T", respMsg)
	}

	if resp.Cause != nil {
		cause, cErr := resp.Cause.Cause()
		if cErr == nil && cause != ie.CauseRequestAccepted {
			m.stats.RecordFailure(msgTypeName)
			m.stats.RecordSessionFailed()
			session.State = "failed"
			return nil, fmt.Errorf("Session Establishment rejected with cause %d", cause)
		}
	}

	remoteSEID, err := pfcp.ExtractRemoteSEID(resp)
	if err != nil {
		m.stats.RecordFailure(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to extract remote SEID: %w", err)
	}

	m.mu.Lock()
	session.RemoteSEID = remoteSEID
	session.State = "established"
	m.mu.Unlock()

	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	m.stats.RecordSessionEstablished()

	log.WithFields(log.Fields{
		"seq_num":       seqNum,
		"local_seid":    localSEID,
		"remote_seid":   remoteSEID,
		"ue_ip":         ueIP,
		"response_time": result.ResponseTime.Round(time.Microsecond),
	}).Debug("Session established")

	return session, nil
}

// sendPreEncodedModification sends a pre-encoded Session Modification Request,
// patching the header SEID (remoteSEID), UE IP, and seq num by byte-copying the template.
func (m *Manager) sendPreEncodedModification(ctx context.Context, pre *pfcp.PreEncodedMsg, session *types.SessionInfo) error {
	seqNum := m.seqCounter.Next()

	data := make([]byte, len(pre.Data))
	pre.ApplyInto(data, seqNum, session.RemoteSEID, 0 /* no CP-FSEID in modifications */, session.UEIP)

	msgTypeName := "SessionModificationRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return fmt.Errorf("failed to send Session Modification: %w", err)
	}

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		return fmt.Errorf("Session Modification timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionModificationResponse")
	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	m.stats.RecordSessionModified()
	return nil
}

// establishFromRaw decodes a raw establishment message and establishes the session.
func (m *Manager) establishFromRaw(ctx context.Context, raw types.RawPFCPMessage) (*types.SessionInfo, error) {
	msg, err := pfcp.Decode(raw.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode establishment: %w", err)
	}
	return m.handleSessionEstablishment(ctx, msg)
}

// executeSessionTemplate runs a single session lifecycle (Est + Mods + Del).
// In stress mode, each execution tracks its own session locally and auto-generates
// a deletion if the template doesn't have one, ensuring sessions are always cleaned up.
func (m *Manager) executeSessionTemplate(ctx context.Context, tmpl *SessionTemplate, rateLimiter *RateLimiter) error {
	var session *types.SessionInfo

	for _, raw := range tmpl.Messages {
		if err := rateLimiter.Wait(ctx); err != nil {
			// If we got interrupted after establishing, clean up
			if session != nil && session.State == "established" {
				m.cleanupStressSession(ctx, session)
			}
			return err
		}

		msg, err := pfcp.Decode(raw.Data)
		if err != nil {
			return fmt.Errorf("failed to decode message: %w", err)
		}

		switch msg.MessageType() {
		case message.MsgTypeSessionEstablishmentRequest:
			s, err := m.handleSessionEstablishment(ctx, msg)
			if err != nil {
				return err
			}
			session = s

		case message.MsgTypeSessionModificationRequest:
			if session == nil || session.RemoteSEID == 0 {
				return fmt.Errorf("modification without established session")
			}
			if err := m.handleSessionModificationDirect(ctx, msg, session); err != nil {
				return err
			}

		case message.MsgTypeSessionDeletionRequest:
			if session == nil || session.RemoteSEID == 0 {
				return fmt.Errorf("deletion without established session")
			}
			if err := m.handleSessionDeletionDirect(ctx, msg, session); err != nil {
				return err
			}
			session = nil // deleted

		default:
			if err := m.processMessage(ctx, msg, raw); err != nil {
				return err
			}
		}
	}

	// Auto-delete if template didn't include deletion
	if session != nil && session.State == "established" {
		if err := rateLimiter.Wait(ctx); err != nil {
			m.cleanupStressSession(ctx, session)
			return err
		}
		if err := m.sendSessionDeletion(ctx, session); err != nil {
			// Best-effort cleanup on failure
			m.cleanupStressSession(ctx, session)
			return err
		}
	}

	return nil
}

func (m *Manager) processMessage(ctx context.Context, msg message.Message, raw types.RawPFCPMessage) error {
	switch msg.MessageType() {
	case message.MsgTypeAssociationSetupRequest:
		return m.handleAssociationSetup(ctx, msg)
	case message.MsgTypeSessionEstablishmentRequest:
		_, err := m.handleSessionEstablishment(ctx, msg)
		return err
	case message.MsgTypeSessionModificationRequest:
		return m.handleSessionModification(ctx, msg)
	case message.MsgTypeSessionDeletionRequest:
		return m.handleSessionDeletion(ctx, msg)
	case message.MsgTypeHeartbeatRequest:
		return m.handleHeartbeat(ctx, msg)
	default:
		log.WithField("msg_type", pfcp.MessageTypeName(msg.MessageType())).Debug("Skipping unsupported message type")
		return nil
	}
}

func (m *Manager) handleAssociationSetup(ctx context.Context, msg message.Message) error {
	if !m.cfg.Association.Enabled {
		log.Info("Association Setup disabled by configuration, skipping")
		return nil
	}

	req, ok := msg.(*message.AssociationSetupRequest)
	if !ok {
		return fmt.Errorf("unexpected message type for Association Setup")
	}

	seqNum := m.seqCounter.Next()
	if err := m.modifier.ModifyAssociationSetup(req, seqNum); err != nil {
		return fmt.Errorf("failed to modify Association Setup: %w", err)
	}

	data, err := pfcp.Encode(req)
	if err != nil {
		return fmt.Errorf("failed to encode Association Setup: %w", err)
	}

	msgTypeName := "AssociationSetupRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return fmt.Errorf("failed to send Association Setup: %w", err)
	}

	log.WithField("seq_num", seqNum).Info("Sent Association Setup Request")

	// Wait for response
	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		return fmt.Errorf("Association Setup failed: %w", result.Error)
	}

	m.stats.RecordReceived("AssociationSetupResponse")
	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	log.WithFields(log.Fields{
		"seq_num":       seqNum,
		"response_time": result.ResponseTime.Round(time.Microsecond),
	}).Info("Association Setup successful")

	return nil
}

func (m *Manager) handleSessionEstablishment(ctx context.Context, msg message.Message) (*types.SessionInfo, error) {
	req, ok := msg.(*message.SessionEstablishmentRequest)
	if !ok {
		return nil, fmt.Errorf("unexpected message type for Session Establishment")
	}

	// Extract original CP SEID for mapping
	originalCPSEID, err := pfcp.ExtractCPSEID(req)
	if err != nil {
		log.WithError(err).Warn("Could not extract original CP SEID, using 0")
		originalCPSEID = 0
	}

	// Allocate new identifiers
	localSEID, err := m.seidAlloc.Allocate()
	if err != nil {
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to allocate SEID: %w", err)
	}

	ueIP, err := m.ipPool.Allocate()
	if err != nil {
		m.seidAlloc.Release(localSEID)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to allocate UE IP: %w", err)
	}

	// Create session info
	session := &types.SessionInfo{
		OriginalCPSEID: originalCPSEID,
		LocalSEID:      localSEID,
		UEIP:           ueIP,
		State:          "establishing",
		CreatedAt:      time.Now(),
	}

	// Store mapping
	m.mu.Lock()
	m.byOriginalCPSEID[originalCPSEID] = session
	m.byLocalSEID[localSEID] = session
	// Register original remote SEID mapping from pcap if available
	if origRemoteSEID, ok := m.originalSEIDMappings[originalCPSEID]; ok {
		session.OriginalRemoteSEID = origRemoteSEID
		m.byOriginalRemoteSEID[origRemoteSEID] = session
	}
	m.mu.Unlock()

	// Modify message
	seqNum := m.seqCounter.Next()
	if err := m.modifier.ModifySessionEstablishment(req, localSEID, ueIP, seqNum); err != nil {
		return nil, fmt.Errorf("failed to modify Session Establishment: %w", err)
	}

	data, err := pfcp.Encode(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Session Establishment: %w", err)
	}

	msgTypeName := "SessionEstablishmentRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return nil, fmt.Errorf("failed to send Session Establishment: %w", err)
	}

	log.WithFields(log.Fields{
		"seq_num":    seqNum,
		"local_seid": localSEID,
		"ue_ip":      ueIP,
		"orig_seid":  originalCPSEID,
	}).Debug("Sent Session Establishment Request")

	// Wait for response
	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		m.stats.RecordSessionFailed()
		session.State = "failed"
		return nil, fmt.Errorf("Session Establishment timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionEstablishmentResponse")

	// Parse response to extract remote SEID
	respMsg, err := pfcp.Decode(result.Response)
	if err != nil {
		m.stats.RecordFailure(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to decode Establishment Response: %w", err)
	}

	resp, ok := respMsg.(*message.SessionEstablishmentResponse)
	if !ok {
		m.stats.RecordFailure(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("unexpected response type: %T", respMsg)
	}

	// Check cause
	if resp.Cause != nil {
		cause, err := resp.Cause.Cause()
		if err == nil && cause != ie.CauseRequestAccepted {
			m.stats.RecordFailure(msgTypeName)
			m.stats.RecordSessionFailed()
			session.State = "failed"
			return nil, fmt.Errorf("Session Establishment rejected with cause %d", cause)
		}
	}

	// Extract remote SEID
	remoteSEID, err := pfcp.ExtractRemoteSEID(resp)
	if err != nil {
		m.stats.RecordFailure(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to extract remote SEID: %w", err)
	}

	// Update session
	m.mu.Lock()
	session.RemoteSEID = remoteSEID
	session.State = "established"
	m.mu.Unlock()

	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	m.stats.RecordSessionEstablished()

	log.WithFields(log.Fields{
		"seq_num":       seqNum,
		"local_seid":    localSEID,
		"remote_seid":   remoteSEID,
		"ue_ip":         ueIP,
		"response_time": result.ResponseTime.Round(time.Microsecond),
	}).Debug("Session established")

	return session, nil
}

func (m *Manager) handleSessionModification(ctx context.Context, msg message.Message) error {
	req, ok := msg.(*message.SessionModificationRequest)
	if !ok {
		return fmt.Errorf("unexpected message type for Session Modification")
	}

	// The header SEID in the pcap is the original UPF's remote SEID
	originalRemoteSEID := pfcp.ExtractHeaderSEID(msg)

	// Look up session by original remote SEID
	session := m.findSessionByOriginalRemoteSEID(originalRemoteSEID)
	if session == nil {
		return fmt.Errorf("no session found for original remote SEID %d", originalRemoteSEID)
	}

	seqNum := m.seqCounter.Next()
	if err := m.modifier.ModifySessionModification(req, session.RemoteSEID, session.UEIP, seqNum); err != nil {
		return fmt.Errorf("failed to modify Session Modification: %w", err)
	}

	data, err := pfcp.Encode(req)
	if err != nil {
		return fmt.Errorf("failed to encode Session Modification: %w", err)
	}

	msgTypeName := "SessionModificationRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return fmt.Errorf("failed to send Session Modification: %w", err)
	}

	log.WithFields(log.Fields{
		"seq_num":     seqNum,
		"remote_seid": session.RemoteSEID,
		"local_seid":  session.LocalSEID,
	}).Debug("Sent Session Modification Request")

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		return fmt.Errorf("Session Modification timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionModificationResponse")
	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	m.stats.RecordSessionModified()

	log.WithFields(log.Fields{
		"seq_num":       seqNum,
		"response_time": result.ResponseTime.Round(time.Microsecond),
	}).Debug("Session modified")

	return nil
}

func (m *Manager) handleSessionDeletion(ctx context.Context, msg message.Message) error {
	req, ok := msg.(*message.SessionDeletionRequest)
	if !ok {
		return fmt.Errorf("unexpected message type for Session Deletion")
	}

	// The header SEID in the pcap is the original UPF's remote SEID
	originalRemoteSEID := pfcp.ExtractHeaderSEID(msg)

	session := m.findSessionByOriginalRemoteSEID(originalRemoteSEID)
	if session == nil {
		return fmt.Errorf("no session found for original remote SEID %d", originalRemoteSEID)
	}

	seqNum := m.seqCounter.Next()
	if err := m.modifier.ModifySessionDeletion(req, session.RemoteSEID, seqNum); err != nil {
		return fmt.Errorf("failed to modify Session Deletion: %w", err)
	}

	data, err := pfcp.Encode(req)
	if err != nil {
		return fmt.Errorf("failed to encode Session Deletion: %w", err)
	}

	msgTypeName := "SessionDeletionRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return fmt.Errorf("failed to send Session Deletion: %w", err)
	}

	log.WithFields(log.Fields{
		"seq_num":     seqNum,
		"remote_seid": session.RemoteSEID,
		"local_seid":  session.LocalSEID,
	}).Debug("Sent Session Deletion Request")

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		return fmt.Errorf("Session Deletion timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionDeletionResponse")
	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	m.stats.RecordSessionDeleted()

	m.releaseSession(session)

	log.WithFields(log.Fields{
		"seq_num":       seqNum,
		"local_seid":    session.LocalSEID,
		"response_time": result.ResponseTime.Round(time.Microsecond),
	}).Debug("Session deleted")

	return nil
}

// handleSessionModificationDirect modifies a session using a direct session reference
// instead of looking up by original SEID (used in stress mode).
func (m *Manager) handleSessionModificationDirect(ctx context.Context, msg message.Message, session *types.SessionInfo) error {
	req, ok := msg.(*message.SessionModificationRequest)
	if !ok {
		return fmt.Errorf("unexpected message type for Session Modification")
	}

	seqNum := m.seqCounter.Next()
	if err := m.modifier.ModifySessionModification(req, session.RemoteSEID, session.UEIP, seqNum); err != nil {
		return fmt.Errorf("failed to modify Session Modification: %w", err)
	}

	data, err := pfcp.Encode(req)
	if err != nil {
		return fmt.Errorf("failed to encode Session Modification: %w", err)
	}

	msgTypeName := "SessionModificationRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return fmt.Errorf("failed to send Session Modification: %w", err)
	}

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		return fmt.Errorf("Session Modification timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionModificationResponse")
	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	m.stats.RecordSessionModified()
	return nil
}

// handleSessionDeletionDirect deletes a session using a direct session reference
// instead of looking up by original SEID (used in stress mode).
func (m *Manager) handleSessionDeletionDirect(ctx context.Context, msg message.Message, session *types.SessionInfo) error {
	req, ok := msg.(*message.SessionDeletionRequest)
	if !ok {
		return fmt.Errorf("unexpected message type for Session Deletion")
	}

	seqNum := m.seqCounter.Next()
	if err := m.modifier.ModifySessionDeletion(req, session.RemoteSEID, seqNum); err != nil {
		return fmt.Errorf("failed to modify Session Deletion: %w", err)
	}

	data, err := pfcp.Encode(req)
	if err != nil {
		return fmt.Errorf("failed to encode Session Deletion: %w", err)
	}

	msgTypeName := "SessionDeletionRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return fmt.Errorf("failed to send Session Deletion: %w", err)
	}

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		return fmt.Errorf("Session Deletion timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionDeletionResponse")
	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	m.stats.RecordSessionDeleted()

	m.releaseSession(session)
	return nil
}

// sendSessionDeletion generates and sends a Session Deletion Request for a session
// that doesn't have one in its template (auto-cleanup in stress mode).
func (m *Manager) sendSessionDeletion(ctx context.Context, session *types.SessionInfo) error {
	seqNum := m.seqCounter.Next()
	req := message.NewSessionDeletionRequest(0, 0, session.RemoteSEID, seqNum, 0)

	data, err := pfcp.Encode(req)
	if err != nil {
		return fmt.Errorf("failed to encode auto-deletion: %w", err)
	}

	msgTypeName := "SessionDeletionRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return fmt.Errorf("failed to send auto-deletion: %w", err)
	}

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		return fmt.Errorf("auto-deletion timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionDeletionResponse")
	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)
	m.stats.RecordSessionDeleted()

	m.releaseSession(session)
	return nil
}

// cleanupStressSession releases session resources without sending a deletion
// to the UPF (used when context is cancelled or errors occur).
func (m *Manager) cleanupStressSession(ctx context.Context, session *types.SessionInfo) {
	m.releaseSession(session)
}

// releaseSession frees SEID, UE IP and removes session from maps.
func (m *Manager) releaseSession(session *types.SessionInfo) {
	m.seidAlloc.Release(session.LocalSEID)
	if session.UEIP != nil {
		m.ipPool.Release(session.UEIP)
	}

	m.mu.Lock()
	session.State = "deleted"
	delete(m.byLocalSEID, session.LocalSEID)
	delete(m.byOriginalCPSEID, session.OriginalCPSEID)
	if session.OriginalRemoteSEID != 0 {
		delete(m.byOriginalRemoteSEID, session.OriginalRemoteSEID)
	}
	m.mu.Unlock()
}

func (m *Manager) handleHeartbeat(ctx context.Context, msg message.Message) error {
	req, ok := msg.(*message.HeartbeatRequest)
	if !ok {
		return fmt.Errorf("unexpected message type for Heartbeat")
	}

	seqNum := m.seqCounter.Next()
	if err := m.modifier.ModifyHeartbeat(req, seqNum); err != nil {
		return fmt.Errorf("failed to modify Heartbeat: %w", err)
	}

	data, err := pfcp.Encode(req)
	if err != nil {
		return fmt.Errorf("failed to encode Heartbeat: %w", err)
	}

	msgTypeName := "HeartbeatRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return fmt.Errorf("failed to send Heartbeat: %w", err)
	}

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		return fmt.Errorf("Heartbeat timeout: %w", result.Error)
	}

	m.stats.RecordReceived("HeartbeatResponse")
	m.stats.RecordSuccess(msgTypeName, result.ResponseTime)

	return nil
}

// CleanupSessions sends Session Deletion for all active sessions.
func (m *Manager) CleanupSessions(ctx context.Context) {
	m.mu.RLock()
	var activeSessions []*types.SessionInfo
	for _, s := range m.byLocalSEID {
		if s.State == "established" {
			activeSessions = append(activeSessions, s)
		}
	}
	m.mu.RUnlock()

	if len(activeSessions) == 0 {
		return
	}

	log.WithField("count", len(activeSessions)).Info("Cleaning up active sessions")

	for _, session := range activeSessions {
		select {
		case <-ctx.Done():
			return
		default:
		}

		seqNum := m.seqCounter.Next()
		req := message.NewSessionDeletionRequest(0, 0, session.RemoteSEID, seqNum, 0)

		data, err := pfcp.Encode(req)
		if err != nil {
			log.WithError(err).WithField("local_seid", session.LocalSEID).Error("Failed to encode cleanup deletion")
			continue
		}

		portIdx := m.pool.NextPortIndex()
		resultCh := m.tracker.Track(seqNum, data, portIdx)
		if err := m.pool.SendOn(portIdx, data); err != nil {
			log.WithError(err).WithField("local_seid", session.LocalSEID).Error("Failed to send cleanup deletion")
			continue
		}

		result := m.waitForResult(ctx, resultCh)
		if result.Error != nil {
			log.WithError(result.Error).WithField("local_seid", session.LocalSEID).Warn("Cleanup deletion failed")
		} else {
			m.stats.RecordSessionDeleted()
			m.mu.Lock()
			session.State = "deleted"
			m.mu.Unlock()
		}
	}
}

// handleResponses processes incoming PFCP messages from the UPF.
func (m *Manager) handleResponses(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case received, ok := <-m.receiver.Messages():
			if !ok {
				return
			}
			seqNum := received.Message.Sequence()
			m.tracker.Resolve(seqNum, received.Message, received.Data)
		}
	}
}

// findSessionByOriginalRemoteSEID finds a session using the original remote SEID from the pcap.
func (m *Manager) findSessionByOriginalRemoteSEID(originalRemoteSEID uint64) *types.SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// First try direct lookup
	if session, ok := m.byOriginalRemoteSEID[originalRemoteSEID]; ok {
		return session
	}

	// If not found, the pcap might use the original CP SEID as the header SEID
	// in modification/deletion requests (this depends on pcap capture perspective)
	if session, ok := m.byOriginalCPSEID[originalRemoteSEID]; ok {
		return session
	}

	return nil
}

// RegisterOriginalRemoteSEID registers the original remote SEID mapping from pcap responses.
func (m *Manager) RegisterOriginalRemoteSEID(originalRemoteSEID uint64, session *types.SessionInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session.OriginalRemoteSEID = originalRemoteSEID
	m.byOriginalRemoteSEID[originalRemoteSEID] = session
}

// ActiveSessionCount returns the number of currently active sessions.
func (m *Manager) ActiveSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, s := range m.byLocalSEID {
		if s.State == "established" {
			count++
		}
	}
	return count
}

func (m *Manager) waitForResult(ctx context.Context, resultCh <-chan types.TransactionResult) types.TransactionResult {
	select {
	case <-ctx.Done():
		return types.TransactionResult{Error: ctx.Err()}
	case result := <-resultCh:
		return result
	}
}
