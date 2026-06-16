# TPS-First Stress Controller — Redesign Proposal

**Status**: Proposed (replaces the current PI-controller mechanism entirely)
**Audience**: implementer of the new stress-mode control path

## 1. Problem

The current stress-mode TPS control is unstable. Two coupled causes:

1. **Send rate is coupled to RTT.** Workers in `executeStressSession`
   (`internal/session/manager.go:770-850`) block on responses (`waitForResult`)
   inside the session lifecycle. When UPF RTT rises, workers stall and the send
   rate collapses, even though the token bucket has tokens available.
2. **A feedback loop fights the symptom.** A PI controller
   (`internal/session/picontroller.go`) — with plant-gain estimation from a
   lifetime sampler, anti-windup, an adaptive pre-deletion delay, a deletion
   dispatcher, and a worker autoscaler — tries to pin active sessions to an
   exact setpoint. The plant-gain estimate (`observedTPS / msgsPerLifecycle`)
   is noisy, so the loop oscillates, and the oscillation feeds back into TPS.

## 2. Requirements

- **TPS is the ultimate controlled variable.** It must hold flat at the target
  even when RTT, response delay, or other metrics degrade — those metrics are
  allowed to break.
- **TPS settable dynamically at runtime** (existing TCP control server).
- **Active sessions need only stay within 60%–100% of target.** No precise
  setpoint, no controller.
- **Simple.** No control theory, no adaptive tuning, no autoscaling.

## 3. Design

### 3.1 Core principle

> One rate-limiter token authorizes exactly one PFCP request send
> (establish, modify, or delete — all count equally as a transaction).
> **Nothing in the send-decision path ever blocks on the network.**

The existing `RateLimiter` (`internal/session/ratelimiter.go`) is reused
unchanged as the single TPS authority — it already supports atomic dynamic
`SetTPS()` with ~1ms latency and self-correcting per-tick accounting.

### 3.2 Components

```
control server ──▶ control.StressParams (atomic TPS, target sessions)   [kept as-is]
                        │ GetTPS                 │ GetActiveSessions
                        ▼                        ▼
              ┌──────────────┐      ┌─────────────────────────────────┐
              │ RateLimiter  │◀─────│ SCHEDULER (single goroutine)     │
              │ (kept as-is) │Wait()│ owns: sendQ, livePool, counters  │
              └──────────────┘      │ drain establishedCh/FailedCh,    │
                                    │ then pick ONE job (P1..P5)       │
                                    └───────────┬─────────────────────┘
                                                │ jobCh (buffered ~4× senders)
                                                ▼
                              SENDER POOL (NumCPU×4, fixed, stateless)
                              ApplyInto → tracker.TrackWith → SendOn
                              (NEVER waits for responses)
                                                │
                  ┌─────────────────────────────┴──────────────────┐
                  ▼                                                ▼
        estSharedCh → establish collectors (tiny pool):   statsSharedCh → drainers (tiny pool):
        extract RemoteSEID, emit established/failed       record success / timeout / RTT only;
        events back to scheduler                          never gates the scheduler
```

### 3.3 Scheduler: one token, one decision, O(1)

A **single goroutine** owns all queues and counters (single-writer — no locks).
Loop body:

1. Non-blocking drain of `establishedCh` / `establishFailedCh` to update state.
2. `rateLimiter.Wait(ctx)` for one token.
3. Re-read `params.GetTPS()` / `params.GetActiveSessions()` on a 1s tick (not
   per token); on TPS change call `rateLimiter.SetTPS()`.
4. Pick exactly **one** job by priority and push it to `jobCh`:

| Pri | Condition | Action |
|-----|-----------|--------|
| P1 | `sendQ` non-empty (ready mods/deletes for sessions that have RemoteSEID) | send head |
| P2 | `activeSessions >= target` and `livePool` non-empty | delete oldest (ceiling) |
| P3 | `activeSessions < target` and `inFlight < maxInFlight` (= k×target, k=2) | start new establish |
| P4 | `livePool` non-empty | delete oldest (churn keeps TPS when band is full or establishes can't complete) |
| P5 | — | forfeit token, increment `StarvedTokens` (network-fully-broken case only) |

Definitions:
- `activeSessions` = establish response received, delete not yet sent.
- `inFlight` = SEID/IP allocated, not yet freed.

**The 60–100% band emerges as a sawtooth** — establish up to the ceiling, then
delete down — with no controller. Behavior under dynamics:

- **Target lowered at runtime** (`activeSessions > newTarget`): P2 drains the
  excess at the token rate; the band re-converges as a downward sawtooth.
- **RTT spike**: outstanding establishes accumulate until `inFlight` hits
  `maxInFlight`, P3 stops, P1/P2/P4 keep consuming tokens — **TPS stays flat**.
  Active sessions may transiently dip below 60%; acceptable per requirements.
- **TPS raised at runtime**: takes effect within ~1ms via `SetTPS`.

Do **not** shard the scheduler. At 500k TPS it performs ~4 channel ops per
token (~2M ops/s), well within one core; sharding would break the global band
and oldest-first ordering. If profiling ever shows saturation, batch K tokens
per loop iteration instead.

### 3.4 Response handling — the decoupling

Only the **establish response** gates anything (it carries the RemoteSEID
needed to address subsequent messages). Modify/delete responses feed stats only.

**No goroutine per outstanding transaction.** Add to
`internal/network/transaction.go`:

```go
// TrackWith is Track() but resolves into a caller-supplied shared channel.
func (t *TransactionTracker) TrackWith(seqNum uint32, requestData []byte,
    portIndex int, shared chan types.TransactionResult)
```

- `PendingTransaction` gains `Owner *types.SessionInfo`;
  `types.TransactionResult` gains `Owner`, set by `Resolve`/`handleTimeout`.
  Collectors need **no seq→session map** — the session pointer rides in the
  result. `Resolve` deletes the pending entry under the shard lock before
  pushing (`transaction.go:91`), so exactly one result is delivered per seqNum
  (retransmit-safe, no double counting).
- **`estSharedCh`** (generously buffered): a fixed pool (~NumCPU) of collectors
  calls `pfcp.ExtractEstablishmentResponseFast` (`internal/pfcp/preencoded.go:287`),
  sets `session.RemoteSEID`, and emits the session to `establishedCh` or
  `establishFailedCh`. On failure the collector also releases SEID/IP.
- **`statsSharedCh`** (buffer ~64k): drainers record
  `RecordSuccess`/`RecordTimeout`/RTT. The push into this channel from
  `Resolve`/`handleTimeout` must be **non-blocking** (`select`/`default`,
  drop + count) so a stalled stats drain can never block the single
  `handleResponses` goroutine (`manager.go:1595`) and thereby stall establishes.
  Dropping stats results under extreme backpressure is acceptable; stalling
  establishes is not. The establish channel keeps blocking semantics (its
  results gate progress) plus a generous buffer.

### 3.5 Session state and mod progress

- `types.SessionInfo` gains `ModsRemaining int`, `NextModIdx int`,
  `TemplateIdx int`. The scheduler is the sole writer — plain ints, no atomics.
- On an `establishedCh` event, the scheduler increments `activeSessions` and
  enqueues the session into `sendQ` (its mods are sent in template order).
  When the last mod is popped/sent, the session moves to `livePool` (FIFO —
  oldest-first deletion).
- Sessions with zero mods go straight to `livePool`.

### 3.6 Resource cleanup

**Free SEID/IP and decrement `inFlight` on delete SEND**, not on the delete
response (same as today, `manager.go:674-675`). Rationale: waiting on delete
responses would reintroduce RTT-coupled tracking, and the IP pool is already a
FIFO cooldown ring — released IPs go to the back and are reused last
(`internal/session/ip_pool.go:104-105`) — so immediate release still yields
maximum cooldown. Accepted trade-off: a lost delete leaves a stale session on
the UPF; the stats drainer records the timeout.

Shutdown ordering: cancel the scheduler first, close `jobCh`, let senders
drain, then collectors/drainers exit; `CleanupSessions` (`manager.go:1535`)
deletes whatever remains in `livePool`, and `releaseSessionStress` is called
for anything still `inFlight` to avoid leaking SEID/IP.

### 3.7 Sizing and backpressure

- **Preflight check**: SEID and IP pools must cover `maxInFlight = 2×target`,
  not just target — otherwise `Allocate` errors masquerade as network failures.
- `jobCh` buffer ≈ 4× sender count, so backpressure is prompt: if senders
  can't keep up, the scheduler blocks on `jobCh`, stops draining tokens, and
  `RateLimiter.Dropped` (`ratelimiter.go:81`) climbs. Surface `Dropped` and
  `StarvedTokens` on the dashboard so "TPS unachievable" is visible, not silent.

## 4. Code changes

### Modify

| File | Change |
|------|--------|
| `internal/session/manager.go` | Rewrite `ReplayStress` body. New: `runScheduler`, `runSender`, `runEstablishCollector`, `runStatsDrainer`, `job` struct (`kind` establish/modify/delete, `session`, `templateIdx`). Split `establishFromPreEncoded`: the allocate+ApplyInto+TrackWith+SendOn half stays in the sender; the `waitForResult` + RemoteSEID-extraction half (`manager.go:889-924`) moves into the establish collector. Keep `firePreEncodedModification`, `releaseSessionStress`, and the sequential `Replay` path untouched. |
| `internal/network/transaction.go` | Add `TrackWith`; add `Owner` to `PendingTransaction`; non-blocking push for the shared stats channel. |
| `pkg/types/types.go` | `TransactionResult.Owner`; `SessionInfo.ModsRemaining/NextModIdx/TemplateIdx`. |
| `internal/stats/reporter.go` | Redefine `ControlState` → `{SendQDepth, LivePoolDepth, InFlight, OutstandingEst, StarvedTokens, DroppedTokens}` (keep the `SetControlStateFunc` plumbing). CSV: drop `delay_ms, pi_integral, pi_saturated`; add `sendq_depth, livepool_depth, inflight, outstanding_est, starved_tokens, dropped_tokens`. Dashboard: drop the τ/Integral/SATURATED block. |

### Delete (verified used only by the old stress control)

- `internal/session/picontroller.go` + `picontroller_test.go`
- `internal/session/lifetime_sampler.go` + `lifetime_sampler_test.go`
  (+ `Manager.lifetimeSampler` field, `manager.go:54`)
- `adaptiveDelay`, `pendingSession` (`manager.go:27-30, 192-201`)
- `runDeletionDispatcher` (`manager.go:636-767`)
- `executeStressSession` (`manager.go:770-850`)
- Feeder/semaphore/`workCh`/worker-autoscaler inline in `ReplayStress`
  (`manager.go:256-622`)
- `sendSessionDeletionStress` (`manager.go:1438-1468`, already dead code)

### Keep unchanged

`RateLimiter`, `control.StressParams` + TCP control server,
`TransactionTracker` core (Resolve/timeout/retransmit), SEID allocator,
IP pool, pre-encoded templates, receiver, sequential replay mode.

## 5. Verification

1. `make build && make test`. Add scheduler unit tests — the priority rule is
   pure in-memory logic, easily tested with stub channels: band sawtooth stays
   in 60–100%, target-lowered drain, starvation forfeit, last-mod →
   livePool transition.
2. End-to-end vs mock UPF: `go run ./test/mockupf/ &` then
   `./pfcp-generator --stress --tps N --active-sessions M --csv-file out.csv`;
   assert `current_tps` within a few % of target and `active_sessions` within
   the 60–100% band.
3. **Decoupling acceptance test**: add artificial response delay/jitter (or
   drop a % of responses) in mockupf. TPS must stay flat while RTT/p99
   degrade. This is the defining acceptance criterion.
4. Runtime dynamics via control port: `set tps` up/down and
   `set active-sessions` down mid-run; TPS step response is immediate, band
   re-converges without oscillation.
