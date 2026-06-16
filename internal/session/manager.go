package session

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"pfcp-generator/internal/config"
	"pfcp-generator/internal/control"
	"pfcp-generator/internal/network"
	"pfcp-generator/internal/pfcp"
	"pfcp-generator/internal/stats"
	"pfcp-generator/pkg/types"
)

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
		cfg:                  cfg,
		pool:                 pool,
		receiver:             receiver,
		tracker:              tracker,
		modifier:             modifier,
		seidAlloc:            seidAlloc,
		ipPool:               ipPool,
		stats:                statsCollector,
		seqCounter:           &SequenceCounter{},
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
func (m *Manager) StartResponseHandler(ctx context.Context) {
	go m.handleResponses(ctx)
}

// Reset clears all session state so the manager can be reused for another replay iteration.
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

// ─── Stress Mode ─────────────────────────────────────────────────────────────

// jobKind identifies the type of work in a scheduler job.
type jobKind uint8

const (
	jobEstablish jobKind = iota
	jobModify
	jobDelete
)

// job is a unit of work dispatched by the scheduler to a sender goroutine.
type job struct {
	kind    jobKind
	session *types.SessionInfo
	tmplIdx int // template index (establish uses session.TemplateIdx; modify uses this field)
	modIdx  int // index into tmpl.ModMsgs (for modify)
}

// schedCounters holds atomic counters written by the scheduler for dashboard/logging.
// The dashboard reads these from a separate goroutine, so they are atomic.
type schedCounters struct {
	sendQDepth    atomic.Int64
	livePoolDepth atomic.Int64
	inFlight      atomic.Int64
	activeSess    atomic.Int64
	starved       atomic.Int64
	dropped       *atomic.Int64 // points into RateLimiter.Dropped
}

// ReplayStress runs a high-performance stress test using the given replay plan.
//
// TPS is the ultimate controlled variable: the rate limiter is the single authority
// and nothing in the send path blocks on the network.  Active sessions are held in
// a 60–100% band of the target by a five-rule priority scheduler; no PI controller
// or adaptive delay is used.
func (m *Manager) ReplayStress(ctx context.Context, plan *ReplayPlan, params *control.StressParams, duration time.Duration, reporter *stats.Reporter) error {
	if plan.AssociationSetup != nil && m.cfg.Association.Enabled {
		msg, err := pfcp.Decode(plan.AssociationSetup.Data)
		if err != nil {
			return fmt.Errorf("failed to decode association setup: %w", err)
		}
		if err := m.handleAssociationSetup(ctx, msg); err != nil {
			return fmt.Errorf("association setup failed: %w", err)
		}
	}

	rateLimiter := NewRateLimiter(ctx, params.GetTPS())
	defer rateLimiter.Stop()

	var testCtx context.Context
	var testCancel context.CancelFunc
	if duration > 0 {
		testCtx, testCancel = context.WithTimeout(ctx, duration)
	} else {
		testCtx, testCancel = context.WithCancel(ctx)
	}
	defer testCancel()

	preEncoded := BuildPreEncodedTemplates(plan.Templates, m.modifier)
	if len(preEncoded) == 0 {
		return fmt.Errorf("no templates could be pre-encoded")
	}
	preEncodedDel, err := pfcp.PreEncodeDeletion()
	if err != nil {
		return fmt.Errorf("failed to pre-encode deletion template: %w", err)
	}
	log.WithFields(log.Fields{
		"templates":     len(preEncoded),
		"deletion_size": len(preEncodedDel.Data),
	}).Info("Pre-encoded session templates")

	target := params.GetActiveSessions()
	if m.ipPool.TotalIPs() < 2*target {
		log.Warnf("IP pool (%d IPs) < 2×target (%d); some establishes may fail at peak inFlight",
			m.ipPool.TotalIPs(), 2*target)
	}

	const (
		estSharedBuf   = 100_000
		statsSharedBuf = 1 << 16 // 65536
		estEventBuf    = 10_000
		jobChFactor    = 4
	)
	estSharedCh       := make(chan types.TransactionResult, estSharedBuf)
	statsSharedCh     := make(chan types.TransactionResult, statsSharedBuf)
	establishedCh     := make(chan *types.SessionInfo, estEventBuf)
	establishFailedCh := make(chan *types.SessionInfo, estEventBuf)

	numCPU := runtime.NumCPU()
	senderCount := numCPU * 4
	jobCh := make(chan job, jobChFactor*senderCount)

	ctrs := &schedCounters{dropped: &rateLimiter.Dropped}
	if reporter != nil {
		reporter.SetControlStateFunc(func() stats.ControlState {
			return stats.ControlState{
				SendQDepth:    ctrs.sendQDepth.Load(),
				LivePoolDepth: ctrs.livePoolDepth.Load(),
				InFlight:      ctrs.inFlight.Load(),
				ActiveSess:    ctrs.activeSess.Load(),
				StarvedTokens: ctrs.starved.Load(),
				DroppedTokens: ctrs.dropped.Load(),
			}
		})
	}

	var wg sync.WaitGroup

	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runEstablishCollector(testCtx, estSharedCh, establishedCh, establishFailedCh)
		}()
	}

	drainerCount := numCPU / 2
	if drainerCount < 2 {
		drainerCount = 2
	}
	for i := 0; i < drainerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runStatsDrainer(testCtx, statsSharedCh)
		}()
	}

	for i := 0; i < senderCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runSender(testCtx, jobCh, preEncoded, preEncodedDel, estSharedCh, statsSharedCh)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-testCtx.Done():
				return
			case <-ticker.C:
				elapsed := m.stats.Duration()
				totalSent := m.stats.TotalSent()
				var currentTPS float64
				if elapsed.Seconds() > 0 {
					currentTPS = float64(totalSent) / elapsed.Seconds()
				}
				_, _, _, _, _, rttP99 := m.stats.ResponseTimes.Stats()
				log.WithFields(log.Fields{
					"active":      ctrs.activeSess.Load(),
					"target":      params.GetActiveSessions(),
					"inflight":    ctrs.inFlight.Load(),
					"sendq":       ctrs.sendQDepth.Load(),
					"livepool":    ctrs.livePoolDepth.Load(),
					"starved":     ctrs.starved.Load(),
					"dropped":     ctrs.dropped.Load(),
					"total_sent":  totalSent,
					"current_tps": fmt.Sprintf("%.0f", currentTPS),
					"target_tps":  fmt.Sprintf("%.0f", params.GetTPS()),
					"elapsed":     elapsed.Round(time.Second),
					"rtt_p99_ms":  rttP99.Milliseconds(),
				}).Info("Stress test progress")
			}
		}
	}()

	log.WithFields(log.Fields{
		"target_tps":      params.GetTPS(),
		"target_sessions": target,
		"senders":         senderCount,
		"collectors":      numCPU,
		"drainers":        drainerCount,
	}).Info("Stress test starting")

	m.runScheduler(testCtx, rateLimiter, params, preEncoded, jobCh, establishedCh, establishFailedCh, ctrs)

	close(jobCh)
	wg.Wait()

	log.Info("Stress test completed")
	return nil
}

// runScheduler is the single goroutine that owns all scheduling queues and counters.
// It consumes one rate-limiter token per iteration and dispatches exactly one job.
// Nothing in this path blocks on the network; all I/O happens in runSender.
func (m *Manager) runScheduler(
	ctx context.Context,
	rl *RateLimiter,
	params *control.StressParams,
	preEncoded []PreEncodedTemplate,
	jobCh chan<- job,
	establishedCh <-chan *types.SessionInfo,
	establishFailedCh <-chan *types.SessionInfo,
	ctrs *schedCounters,
) {
	var (
		sendQ    []*types.SessionInfo // sessions with pending mods
		livePool []*types.SessionInfo // active sessions ready for deletion (FIFO)

		activeSessions int // established, delete-send not yet dispatched
		inFlight       int // SEID/IP allocated, not yet freed
		tmplIdx        int // round-robin template counter
		starved        int64

		target      = params.GetActiveSessions()
		curTPS      = params.GetTPS()
		maxInFlight = 2 * target

		lastParamCheck time.Time
	)
	n := len(preEncoded)

	for {
		// Drain event channels non-blocking before each token wait.
	drainEvents:
		for {
			select {
			case sess := <-establishedCh:
				activeSessions++
				if sess.ModsRemaining > 0 {
					sendQ = append(sendQ, sess)
				} else {
					livePool = append(livePool, sess)
				}
			case sess := <-establishFailedCh:
				inFlight-- // collector already released SEID/IP
				_ = sess
			default:
				break drainEvents
			}
		}

		// Re-read params and publish counters ~every second.
		now := time.Now()
		if now.Sub(lastParamCheck) >= time.Second {
			newTPS := params.GetTPS()
			if newTPS != curTPS {
				rl.SetTPS(newTPS)
				log.WithFields(log.Fields{"old": curTPS, "new": newTPS}).Info("Target TPS changed")
				curTPS = newTPS
			}
			newTarget := params.GetActiveSessions()
			if newTarget != target {
				log.WithFields(log.Fields{"old": target, "new": newTarget}).Info("Target sessions changed")
				target = newTarget
				maxInFlight = 2 * target
			}
			ctrs.sendQDepth.Store(int64(len(sendQ)))
			ctrs.livePoolDepth.Store(int64(len(livePool)))
			ctrs.inFlight.Store(int64(inFlight))
			ctrs.activeSess.Store(int64(activeSessions))
			ctrs.starved.Store(starved)
			lastParamCheck = now
		}

		// Wait for one token — the only place the scheduler sleeps.
		if err := rl.Wait(ctx); err != nil {
			return
		}

		// Five-rule priority decision (O(1) in-memory, no network I/O).
		if len(sendQ) > 0 {
			// P1: drain ready modifications (sessions that already have RemoteSEID).
			sess := sendQ[0]
			sendQ = sendQ[1:]
			modIdx := sess.NextModIdx
			sess.NextModIdx++
			sess.ModsRemaining--
			select {
			case jobCh <- job{kind: jobModify, session: sess, tmplIdx: sess.TemplateIdx, modIdx: modIdx}:
			case <-ctx.Done():
				return
			}
			if sess.ModsRemaining > 0 {
				sendQ = append(sendQ, sess)
			} else {
				livePool = append(livePool, sess)
			}

		} else if activeSessions >= target && len(livePool) > 0 {
			// P2: at or above session ceiling — delete oldest.
			sess := livePool[0]
			livePool = livePool[1:]
			activeSessions--
			inFlight--
			select {
			case jobCh <- job{kind: jobDelete, session: sess}:
			case <-ctx.Done():
				return
			}

		} else if activeSessions < target && inFlight < maxInFlight {
			// P3: below target — start a new establish.
			localSEID, err := m.seidAlloc.Allocate()
			if err != nil {
				starved++
			} else if ueIP, err := m.ipPool.Allocate(); err != nil {
				m.seidAlloc.Release(localSEID)
				starved++
			} else {
				ti := tmplIdx % n
				sess := &types.SessionInfo{
					LocalSEID:     localSEID,
					UEIP:          ueIP,
					TemplateIdx:   ti,
					ModsRemaining: len(preEncoded[ti].ModMsgs),
					NextModIdx:    0,
					State:         "establishing",
					CreatedAt:     time.Now(),
				}
				tmplIdx++
				inFlight++
				select {
				case jobCh <- job{kind: jobEstablish, session: sess}:
				case <-ctx.Done():
					m.seidAlloc.Release(localSEID)
					m.ipPool.Release(ueIP)
					inFlight--
					return
				}
			}

		} else if len(livePool) > 0 {
			// P4: band full or inFlight at cap — churn-delete to keep TPS alive.
			sess := livePool[0]
			livePool = livePool[1:]
			activeSessions--
			inFlight--
			select {
			case jobCh <- job{kind: jobDelete, session: sess}:
			case <-ctx.Done():
				return
			}

		} else {
			// P5: nothing actionable — forfeit token.
			starved++
		}
	}
}

// runSender reads jobs from jobCh and executes them as fire-and-forget UDP sends.
// It never blocks waiting for a response; all response handling happens elsewhere.
func (m *Manager) runSender(
	ctx context.Context,
	jobCh <-chan job,
	preEncoded []PreEncodedTemplate,
	preEncodedDel *pfcp.PreEncodedMsg,
	estSharedCh chan types.TransactionResult,
	statsSharedCh chan types.TransactionResult,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case j, ok := <-jobCh:
			if !ok {
				return
			}
			switch j.kind {
			case jobEstablish:
				tmpl := &preEncoded[j.session.TemplateIdx]
				seqNum := m.seqCounter.Next()
				data := make([]byte, len(tmpl.EstMsg.Data))
				tmpl.EstMsg.ApplyInto(data, seqNum, 0, j.session.LocalSEID, j.session.UEIP)
				m.stats.RecordSent("SessionEstablishmentRequest")
				portIdx := m.pool.NextPortIndex()
				m.tracker.TrackWith(seqNum, data, portIdx, j.session, "SessionEstablishmentRequest", estSharedCh)
				if err := m.pool.SendOn(portIdx, data); err != nil {
					log.WithError(err).Debug("Failed to send Session Establishment")
				}

			case jobModify:
				tmpl := &preEncoded[j.tmplIdx]
				modMsg := tmpl.ModMsgs[j.modIdx]
				seqNum := m.seqCounter.Next()
				data := make([]byte, len(modMsg.Data))
				modMsg.ApplyInto(data, seqNum, j.session.RemoteSEID, 0, j.session.UEIP)
				m.stats.RecordSent("SessionModificationRequest")
				portIdx := m.pool.NextPortIndex()
				m.tracker.TrackWith(seqNum, data, portIdx, j.session, "SessionModificationRequest", statsSharedCh)
				if err := m.pool.SendOn(portIdx, data); err != nil {
					log.WithError(err).Debug("Failed to send Session Modification")
				}

			case jobDelete:
				seqNum := m.seqCounter.Next()
				data := make([]byte, len(preEncodedDel.Data))
				preEncodedDel.ApplyInto(data, seqNum, j.session.RemoteSEID, 0, nil)
				m.stats.RecordSent("SessionDeletionRequest")
				portIdx := m.pool.NextPortIndex()
				m.tracker.TrackWith(seqNum, data, portIdx, j.session, "SessionDeletionRequest", statsSharedCh)
				if err := m.pool.SendOn(portIdx, data); err != nil {
					log.WithError(err).Debug("Failed to send Session Deletion")
				}
				m.stats.RecordSessionDeleted()
				m.releaseSessionStress(j.session)
			}
		}
	}
}

// runEstablishCollector drains estSharedCh, extracts RemoteSEID from responses,
// and emits the session to establishedCh or establishFailedCh for the scheduler.
func (m *Manager) runEstablishCollector(
	ctx context.Context,
	estSharedCh <-chan types.TransactionResult,
	establishedCh chan<- *types.SessionInfo,
	establishFailedCh chan<- *types.SessionInfo,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-estSharedCh:
			if !ok {
				return
			}
			sess := result.Owner
			if sess == nil {
				continue
			}

			if result.Error != nil {
				m.stats.RecordTimeout("SessionEstablishmentRequest")
				m.stats.RecordSessionFailed()
				m.releaseSessionStress(sess)
				select {
				case establishFailedCh <- sess:
				case <-ctx.Done():
					return
				}
				continue
			}

			m.stats.RecordReceived("SessionEstablishmentResponse")
			remoteSEID, cause, err := pfcp.ExtractEstablishmentResponseFast(result.Response)
			if err != nil || cause != pfcp.CauseRequestAccepted {
				m.stats.RecordFailure("SessionEstablishmentRequest")
				m.stats.RecordSessionFailed()
				m.releaseSessionStress(sess)
				select {
				case establishFailedCh <- sess:
				case <-ctx.Done():
					return
				}
				continue
			}

			m.stats.RecordSuccess("SessionEstablishmentRequest", result.ResponseTime)
			m.stats.RecordSessionEstablished()
			sess.RemoteSEID = remoteSEID
			sess.State = "established"
			select {
			case establishedCh <- sess:
			case <-ctx.Done():
				return
			}
		}
	}
}

// runStatsDrainer reads mod/delete results from statsSharedCh and records stats.
// It is stats-only and never signals the scheduler.
func (m *Manager) runStatsDrainer(ctx context.Context, statsSharedCh <-chan types.TransactionResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-statsSharedCh:
			if !ok {
				return
			}
			if result.Error != nil {
				m.stats.RecordTimeout(result.MsgType)
				continue
			}
			// Derive response type: "...Request" → "...Response"
			reqType := result.MsgType
			if len(reqType) > 7 {
				m.stats.RecordReceived(reqType[:len(reqType)-7] + "Response")
			}
			m.stats.RecordSuccess(result.MsgType, result.ResponseTime)
			if result.MsgType == "SessionModificationRequest" {
				m.stats.RecordSessionModified()
			}
		}
	}
}

// ─── Sequential Replay helpers ───────────────────────────────────────────────

// establishFromRaw decodes a raw establishment message and establishes the session.
func (m *Manager) establishFromRaw(ctx context.Context, raw types.RawPFCPMessage) (*types.SessionInfo, error) {
	msg, err := pfcp.Decode(raw.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode establishment: %w", err)
	}
	return m.handleSessionEstablishment(ctx, msg)
}

// executeSessionTemplate runs a single session lifecycle (Est + Mods + Del).
func (m *Manager) executeSessionTemplate(ctx context.Context, tmpl *SessionTemplate, rateLimiter *RateLimiter) error {
	var session *types.SessionInfo

	for _, raw := range tmpl.Messages {
		if err := rateLimiter.Wait(ctx); err != nil {
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
			session = nil

		default:
			if err := m.processMessage(ctx, msg, raw); err != nil {
				return err
			}
		}
	}

	if session != nil && session.State == "established" {
		if err := rateLimiter.Wait(ctx); err != nil {
			m.cleanupStressSession(ctx, session)
			return err
		}
		if err := m.sendSessionDeletion(ctx, session); err != nil {
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

	originalCPSEID, err := pfcp.ExtractCPSEID(req)
	if err != nil {
		log.WithError(err).Warn("Could not extract original CP SEID, using 0")
		originalCPSEID = 0
	}

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
		OriginalCPSEID: originalCPSEID,
		LocalSEID:      localSEID,
		UEIP:           ueIP,
		State:          "establishing",
		CreatedAt:      time.Now(),
	}

	m.mu.Lock()
	m.byOriginalCPSEID[originalCPSEID] = session
	m.byLocalSEID[localSEID] = session
	if origRemoteSEID, ok := m.originalSEIDMappings[originalCPSEID]; ok {
		session.OriginalRemoteSEID = origRemoteSEID
		m.byOriginalRemoteSEID[origRemoteSEID] = session
	}
	m.mu.Unlock()

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

	result := m.waitForResult(ctx, resultCh)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		m.stats.RecordSessionFailed()
		session.State = "failed"
		return nil, fmt.Errorf("Session Establishment timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionEstablishmentResponse")

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
		cause, err := resp.Cause.Cause()
		if err == nil && cause != ie.CauseRequestAccepted {
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

func (m *Manager) handleSessionModification(ctx context.Context, msg message.Message) error {
	req, ok := msg.(*message.SessionModificationRequest)
	if !ok {
		return fmt.Errorf("unexpected message type for Session Modification")
	}

	originalRemoteSEID := pfcp.ExtractHeaderSEID(msg)

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

func (m *Manager) cleanupStressSession(ctx context.Context, session *types.SessionInfo) {
	m.releaseSessionStress(session)
}

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

func (m *Manager) releaseSessionStress(session *types.SessionInfo) {
	m.seidAlloc.Release(session.LocalSEID)
	if session.UEIP != nil {
		m.ipPool.Release(session.UEIP)
	}
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

func (m *Manager) handleResponses(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case received, ok := <-m.receiver.Messages():
			if !ok {
				return
			}
			m.tracker.Resolve(received.SeqNum, received.Data)
		}
	}
}

func (m *Manager) findSessionByOriginalRemoteSEID(originalRemoteSEID uint64) *types.SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if session, ok := m.byOriginalRemoteSEID[originalRemoteSEID]; ok {
		return session
	}

	if session, ok := m.byOriginalCPSEID[originalRemoteSEID]; ok {
		return session
	}

	return nil
}

func (m *Manager) RegisterOriginalRemoteSEID(originalRemoteSEID uint64, session *types.SessionInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session.OriginalRemoteSEID = originalRemoteSEID
	m.byOriginalRemoteSEID[originalRemoteSEID] = session
}

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
