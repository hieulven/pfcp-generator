package session

import (
	"context"
	"fmt"
	"math"
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

// pendingSession is a session that has completed its lifecycle messages and is
// waiting for its adaptive delay to expire before deletion is sent.
type pendingSession struct {
	session  *types.SessionInfo
	deleteAt time.Time
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

	// lifetimeSampler is populated by ReplayStress; read by executeStressSession.
	lifetimeSampler *LifetimeSampler
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
// TPS and active-sessions are read from params at runtime, allowing live tuning
// via the control server without restarting.
func (m *Manager) ReplayStress(ctx context.Context, plan *ReplayPlan, params *control.StressParams, duration time.Duration, reporter *stats.Reporter) error {
	tps := params.GetTPS()
	activeSessions := params.GetActiveSessions()

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

	// Create rate limiter with initial TPS
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

	// Pre-encode all templates once at startup.
	preEncoded := BuildPreEncodedTemplates(plan.Templates, m.modifier)
	if len(preEncoded) == 0 {
		return fmt.Errorf("no templates could be pre-encoded")
	}

	// Pre-encode a deletion template once.
	preEncodedDel, err := pfcp.PreEncodeDeletion()
	if err != nil {
		return fmt.Errorf("failed to pre-encode deletion template: %w", err)
	}
	log.WithFields(log.Fields{
		"templates":     len(preEncoded),
		"deletion_size": len(preEncodedDel.Data),
	}).Info("Pre-encoded session templates")

	// Session semaphore
	sem := make(chan struct{}, activeSessions)

	// pendingCh carries sessions waiting for the adaptive delay before deletion.
	pendingCh := make(chan pendingSession, activeSessions)

	// Work channel
	workCh := make(chan int, activeSessions)

	// Adaptive delay
	delay := &adaptiveDelay{}

	log.WithFields(log.Fields{
		"msgs_per_session": plan.MessagesPerSession,
	}).Info("Stress test starting")

	var completedSessions atomic.Uint64
	var failedSessions atomic.Uint64
	var workersBlockedNet atomic.Int64
	var workersBlockedRate atomic.Int64
	var pendingDelSize atomic.Int64

	// Compute steady-state values from actual pre-encoded templates.
	// Each lifecycle = 1 establishment + N modifications + 1 deletion.
	totalMsgsPerLifecycle := 0
	for _, t := range preEncoded {
		totalMsgsPerLifecycle += 1 + len(t.ModMsgs) + 1
	}
	avgMsgsPerLifecycle := float64(totalMsgsPerLifecycle) / float64(len(preEncoded))

	log.WithFields(log.Fields{
		"msgs_per_lifecycle": fmt.Sprintf("%.1f", avgMsgsPerLifecycle),
	}).Info("Computed steady-state parameters")

	// Create the lifetime sampler before any goroutine is spawned.
	// Worker goroutines in executeStressSession read m.lifetimeSampler;
	// assigning it here (sequenced-before the goroutine launches) avoids
	// a data race with the PI controller goroutine.
	sampler := NewLifetimeSampler(5 * time.Second)
	m.lifetimeSampler = sampler

	// Atomic snapshot for the PI state — read by reporter, written by the PI goroutine.
	// Using atomic uint64 to store float64 bits; no mutex needed for display-only reads.
	var piDelayNs atomic.Int64
	var piIntegralBits atomic.Uint64
	var piSaturatedFlag atomic.Bool
	var piTauBits atomic.Uint64

	// Wire PI state into the reporter dashboard.
	if reporter != nil {
		reporter.SetControlStateFunc(func() stats.ControlState {
			delayNs := piDelayNs.Load()
			integralBits := piIntegralBits.Load()
			tauBits := piTauBits.Load()
			return stats.ControlState{
				Delay:     time.Duration(delayNs),
				Tau:       math.Float64frombits(tauBits),
				Integral:  math.Float64frombits(integralBits),
				Saturated: piSaturatedFlag.Load(),
			}
		})
	}

	// PI controller: closed-loop on active session count.
	// Adjusts pre-deletion delay to drive observed sessions toward target.
	// Open-loop on TPS — the rate limiter caps throughput.
	go func() {
		// sampler is created in ReplayStress setup (above) so worker goroutines
		// can safely read m.lifetimeSampler without a data race.
		pi := NewPIController(0, 60*time.Second)

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		const dt = 1.0
		prevTargetTPS := params.GetTPS()
		prevTargetSess := params.GetActiveSessions()

		var prevSent uint64
		var prevTime time.Time

		for {
			select {
			case <-testCtx.Done():
				return
			case <-ticker.C:
				now := time.Now()

				curTPS := params.GetTPS()
				curSess := params.GetActiveSessions()

				if curTPS != prevTargetTPS {
					rateLimiter.SetTPS(curTPS)
					log.WithFields(log.Fields{
						"old": prevTargetTPS, "new": curTPS,
					}).Info("Target TPS changed")
					prevTargetTPS = curTPS
				}
				if curSess != prevTargetSess {
					log.WithFields(log.Fields{
						"old": prevTargetSess, "new": curSess,
					}).Info("Target sessions changed")
					prevTargetSess = curSess
				}

				// Measure observed TPS
				totalSent := m.stats.TotalSent()
				var observedTPS float64
				if !prevTime.IsZero() {
					elapsed := now.Sub(prevTime).Seconds()
					if elapsed > 0 {
						observedTPS = float64(totalSent-prevSent) / elapsed
					}
				}
				prevSent = totalSent
				prevTime = now

				if observedTPS <= 0 {
					continue
				}

				// Base lifetime: 5s moving average of (establish + mods) duration
				baseLifetime, sampleCount := sampler.Average()
				if sampleCount < 5 {
					continue
				}

				// Update output ceiling based on current base_lifetime
				pi.SetOutputMax(100 * baseLifetime)

				// Plant gain: ∂sessions/∂delay = observedTPS / msgsPerLifecycle
				plantGain := observedTPS / avgMsgsPerLifecycle

				// τ = 2 × (base_lifetime + current_delay); floor at 0.5s
				currentDelay, _ := pi.State()
				tau := 2.0 * (baseLifetime.Seconds() + currentDelay.Seconds())
				if tau < 0.5 {
					tau = 0.5
				}

				activeSessions := int(m.stats.ActiveSessions.Load())

				// Backlog saturation: deletion queue has > 10% of target overdue entries
				// and active sessions are above target — system is throughput-limited.
				backlogSaturated := pendingDelSize.Load() > int64(curSess)/10 &&
					activeSessions > int(float64(curSess)*1.05)

				newDelay := pi.Update(
					float64(activeSessions),
					float64(curSess),
					plantGain,
					tau,
					dt,
					backlogSaturated,
				)
				delay.Set(newDelay)

				// Write atomic snapshot for reporter
				_, integral := pi.State()
				piDelayNs.Store(int64(newDelay))
				piIntegralBits.Store(math.Float64bits(integral))
				piSaturatedFlag.Store(pi.IsSaturated())
				piTauBits.Store(math.Float64bits(tau))

				log.WithFields(log.Fields{
					"observed_tps":     fmt.Sprintf("%.0f", observedTPS),
					"target_tps":       fmt.Sprintf("%.0f", curTPS),
					"observed_sess":    activeSessions,
					"target_sess":      curSess,
					"base_lifetime_ms": baseLifetime.Milliseconds(),
					"delay_ms":         newDelay.Milliseconds(),
					"tau_s":            fmt.Sprintf("%.2f", tau),
					"integral":         fmt.Sprintf("%.2f", integral),
					"saturated":        pi.IsSaturated(),
					"backlog_sat":      backlogSaturated,
				}).Debug("PI controller tick")
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
				_, _, _, _, _, rttP99 := m.stats.ResponseTimes.Stats()
				log.WithFields(log.Fields{
					"completed":    completedSessions.Load(),
					"failed":       failedSessions.Load(),
					"active":       m.stats.ActiveSessions.Load(),
					"total_sent":   totalSent,
					"delay_ms":     delay.Get().Milliseconds(),
					"current_tps":  fmt.Sprintf("%.0f", currentTPS),
					"target_tps":   fmt.Sprintf("%.0f", params.GetTPS()),
					"target_sess":  params.GetActiveSessions(),
					"elapsed":      elapsed.Round(time.Second),
					"workers_net":  workersBlockedNet.Load(),
					"workers_rate": workersBlockedRate.Load(),
					"pending_del":  pendingDelSize.Load(),
					"rtt_p99_ms":   rttP99.Milliseconds(),
				}).Info("Stress test progress")
			}
		}
	}()

	// Deletion dispatcher (FIFO ring buffer)
	go m.runDeletionDispatcher(testCtx, pendingCh, sem, rateLimiter, preEncodedDel, &failedSessions, &pendingDelSize)

	// Feeder goroutine: pushes session templates to workers as sem slots become available.
	// Session count is controlled by the delay (how long sessions live before deletion),
	// not by the feeder. The semaphore caps in-flight sessions at activeSessions.
	go func() {
		defer close(workCh)
		templateCount := len(preEncoded)
		idx := 0
		for {
			select {
			case <-testCtx.Done():
				return
			case sem <- struct{}{}:
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

	// Worker pool with autoscaler
	const (
		scaleUpThreshold = 0.80
		scaleInterval    = 2 * time.Second
	)
	maxWorkers := int(tps * 0.3)
	if maxWorkers < 2000 {
		maxWorkers = 2000
	}
	if maxWorkers > 12000 {
		maxWorkers = 12000
	}
	initialWorkers := int(tps * 0.030)
	if initialWorkers < runtime.NumCPU()*4 {
		initialWorkers = runtime.NumCPU() * 4
	}
	if initialWorkers > maxWorkers {
		initialWorkers = maxWorkers
	}

	var activeWorkerCount atomic.Int64
	var wg sync.WaitGroup

	spawnWorker := func() {
		wg.Add(1)
		activeWorkerCount.Add(1)
		go func() {
			defer wg.Done()
			defer activeWorkerCount.Add(-1)
			for tmplIdx := range workCh {
				tmpl := &preEncoded[tmplIdx]
				err := m.executeStressSession(testCtx, tmpl, rateLimiter, delay, pendingCh,
					&workersBlockedRate, &workersBlockedNet)
				if err != nil {
					if testCtx.Err() != nil {
						<-sem
						return
					}
					failedSessions.Add(1)
					log.WithError(err).Debug("Session failed")
					<-sem
				} else {
					completedSessions.Add(1)
				}
			}
		}()
	}

	log.WithFields(log.Fields{
		"initial_workers": initialWorkers,
		"max_workers":     maxWorkers,
		"active_sessions": activeSessions,
		"target_tps":      tps,
	}).Info("Starting stress workers")

	for w := 0; w < initialWorkers; w++ {
		spawnWorker()
	}

	// Autoscaler
	go func() {
		ticker := time.NewTicker(scaleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-testCtx.Done():
				return
			case <-ticker.C:
				cur := activeWorkerCount.Load()
				if cur <= 0 || cur >= int64(maxWorkers) {
					continue
				}
				netBlocked := workersBlockedNet.Load()
				utilization := float64(netBlocked) / float64(cur)
				if utilization < scaleUpThreshold {
					continue
				}
				needed := int64(float64(netBlocked) / 0.65)
				if needed <= cur {
					needed = int64(float64(cur) * 1.3)
				}
				if needed > int64(maxWorkers) {
					needed = int64(maxWorkers)
				}
				toAdd := needed - cur
				if toAdd < 4 {
					toAdd = 4
				}
				for i := int64(0); i < toAdd; i++ {
					spawnWorker()
				}
				log.WithFields(log.Fields{
					"added":       toAdd,
					"total":       cur + toAdd,
					"utilization": fmt.Sprintf("%.0f%%", utilization*100),
					"net_blocked": netBlocked,
				}).Info("Autoscaled worker pool")
			}
		}
	}()

	wg.Wait()

	log.WithFields(log.Fields{
		"completed":      completedSessions.Load(),
		"failed":         failedSessions.Load(),
		"final_delay_ms": delay.Get().Milliseconds(),
	}).Info("Stress test completed")

	return nil
}

// runDeletionDispatcher manages deferred session deletions using a FIFO ring buffer.
func (m *Manager) runDeletionDispatcher(
	ctx context.Context,
	pendingCh <-chan pendingSession,
	sem chan struct{},
	rateLimiter *RateLimiter,
	preEncodedDel *pfcp.PreEncodedMsg,
	failedSessions *atomic.Uint64,
	pendingDelSize *atomic.Int64,
) {
	const initialCap = 1 << 20
	ring := make([]pendingSession, initialCap)
	head := 0
	tail := 0
	count := 0

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	delBuf := make([]byte, len(preEncodedDel.Data))

	sendDeletion := func(s *types.SessionInfo, buf []byte) {
		seqNum := m.seqCounter.Next()
		preEncodedDel.ApplyInto(buf, seqNum, s.RemoteSEID, 0, nil)

		data := make([]byte, len(buf))
		copy(data, buf)

		m.stats.RecordSent("SessionDeletionRequest")
		portIdx := m.pool.NextPortIndex()

		m.tracker.Track(seqNum, data, portIdx)

		if err := m.pool.SendOn(portIdx, data); err != nil {
			failedSessions.Add(1)
		} else {
			m.stats.RecordSessionDeleted()
		}

		m.releaseSessionStress(s)
		<-sem
	}

	grow := func() {
		newCap := len(ring) * 2
		newRing := make([]pendingSession, newCap)
		if head <= tail {
			copy(newRing, ring[head:tail])
		} else {
			n := copy(newRing, ring[head:])
			copy(newRing[n:], ring[:tail])
		}
		ring = newRing
		head = 0
		tail = count
		log.WithFields(log.Fields{
			"old_cap": len(ring) / 2,
			"new_cap": newCap,
			"count":   count,
		}).Info("Deletion ring buffer grew")
	}

	drainDue := func() {
		now := time.Now()
		for count > 0 {
			entry := &ring[head]
			if entry.deleteAt.After(now) {
				break
			}

			// Non-blocking only. Workers are always running and consuming
			// tokens via Wait(), so the token channel doesn't stagnate.
			// Overdue entries retry on the next 5ms tick.
			if !rateLimiter.TryWait() {
				break
			}

			pendingDelSize.Add(-1)
			sendDeletion(entry.session, delBuf)

			head = (head + 1) % len(ring)
			count--
		}
	}

	for {
		select {
		case <-ctx.Done():
			for count > 0 {
				head = (head + 1) % len(ring)
				count--
				<-sem
			}
			return

		case pd, ok := <-pendingCh:
			if !ok {
				return
			}
			if count == len(ring) {
				grow()
			}
			ring[tail] = pd
			tail = (tail + 1) % len(ring)
			count++
			pendingDelSize.Add(1)

			for i := 0; i < 256; i++ {
				select {
				case pd, ok := <-pendingCh:
					if !ok {
						drainDue()
						return
					}
					if count == len(ring) {
						grow()
					}
					ring[tail] = pd
					tail = (tail + 1) % len(ring)
					count++
					pendingDelSize.Add(1)
				default:
					goto doneReceiving
				}
			}
		doneReceiving:
			drainDue()

		case <-ticker.C:
			drainDue()
		}
	}
}

// executeStressSession runs a session lifecycle using pre-encoded byte templates.
func (m *Manager) executeStressSession(
	ctx context.Context,
	tmpl *PreEncodedTemplate,
	rateLimiter *RateLimiter,
	delay *adaptiveDelay,
	pendingCh chan<- pendingSession,
	workersBlockedRate *atomic.Int64,
	workersBlockedNet *atomic.Int64,
) error {
	// 1. Establish
	workersBlockedRate.Add(1)
	err := rateLimiter.Wait(ctx)
	workersBlockedRate.Add(-1)
	if err != nil {
		return err
	}
	session, err := m.establishFromPreEncoded(ctx, tmpl.EstMsg, workersBlockedNet)
	if err != nil {
		return err
	}

	// 2. Fire all modifications without waiting (pipelined).
	modResults := make([]<-chan types.TransactionResult, 0, len(tmpl.ModMsgs))
	for _, modMsg := range tmpl.ModMsgs {
		workersBlockedRate.Add(1)
		err := rateLimiter.Wait(ctx)
		workersBlockedRate.Add(-1)
		if err != nil {
			m.cleanupStressSession(ctx, session)
			return err
		}
		ch, sendErr := m.firePreEncodedModification(modMsg, session)
		if sendErr != nil {
			if ctx.Err() != nil {
				m.cleanupStressSession(ctx, session)
				return ctx.Err()
			}
			log.WithError(sendErr).Debug("Modification send failed")
			continue
		}
		modResults = append(modResults, ch)
	}

	// Collect all modification responses.
	if len(modResults) > 0 {
		workersBlockedNet.Add(1)
		for _, ch := range modResults {
			result := m.waitForResult(ctx, ch)
			if result.Error != nil {
				if ctx.Err() != nil {
					workersBlockedNet.Add(-1)
					m.cleanupStressSession(ctx, session)
					return ctx.Err()
				}
				m.stats.RecordTimeout("SessionModificationRequest")
			} else {
				m.stats.RecordReceived("SessionModificationResponse")
				m.stats.RecordSuccess("SessionModificationRequest", result.ResponseTime)
				m.stats.RecordSessionModified()
			}
		}
		workersBlockedNet.Add(-1)
	}

	// Record base_lifetime (establish + mods, excluding pre-deletion delay)
	// for the PI controller's gain scheduling.
	if m.lifetimeSampler != nil {
		m.lifetimeSampler.Record(time.Since(session.CreatedAt))
	}

	// 3. Push to deletion dispatcher.
	d := delay.Get()
	deleteAt := time.Now().Add(d)
	select {
	case pendingCh <- pendingSession{session: session, deleteAt: deleteAt}:
		return nil
	case <-ctx.Done():
		m.cleanupStressSession(ctx, session)
		return ctx.Err()
	}
}

// establishFromPreEncoded sends a pre-encoded Session Establishment Request.
func (m *Manager) establishFromPreEncoded(ctx context.Context, pre *pfcp.PreEncodedMsg, workersBlockedNet *atomic.Int64) (*types.SessionInfo, error) {
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

	seqNum := m.seqCounter.Next()

	data := make([]byte, len(pre.Data))
	pre.ApplyInto(data, seqNum, 0, localSEID, ueIP)

	msgTypeName := "SessionEstablishmentRequest"
	m.stats.RecordSent(msgTypeName)
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return nil, fmt.Errorf("failed to send Session Establishment: %w", err)
	}

	workersBlockedNet.Add(1)
	result := m.waitForResult(ctx, resultCh)
	workersBlockedNet.Add(-1)
	if result.Error != nil {
		m.stats.RecordTimeout(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("Session Establishment timeout: %w", result.Error)
	}

	m.stats.RecordReceived("SessionEstablishmentResponse")

	remoteSEID, cause, err := pfcp.ExtractEstablishmentResponseFast(result.Response)
	if err != nil {
		m.stats.RecordFailure(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("failed to parse Establishment Response: %w", err)
	}

	if cause != pfcp.CauseRequestAccepted {
		m.stats.RecordFailure(msgTypeName)
		m.stats.RecordSessionFailed()
		return nil, fmt.Errorf("Session Establishment rejected with cause %d", cause)
	}

	session.RemoteSEID = remoteSEID
	session.State = "established"

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

// firePreEncodedModification sends a pre-encoded Session Modification Request
// and returns the result channel without waiting.
func (m *Manager) firePreEncodedModification(pre *pfcp.PreEncodedMsg, session *types.SessionInfo) (<-chan types.TransactionResult, error) {
	seqNum := m.seqCounter.Next()

	data := make([]byte, len(pre.Data))
	pre.ApplyInto(data, seqNum, session.RemoteSEID, 0, session.UEIP)

	m.stats.RecordSent("SessionModificationRequest")
	portIdx := m.pool.NextPortIndex()
	resultCh := m.tracker.Track(seqNum, data, portIdx)

	if err := m.pool.SendOn(portIdx, data); err != nil {
		return nil, fmt.Errorf("failed to send Session Modification: %w", err)
	}

	return resultCh, nil
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

func (m *Manager) sendSessionDeletionStress(ctx context.Context, session *types.SessionInfo) error {
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

	m.releaseSessionStress(session)
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