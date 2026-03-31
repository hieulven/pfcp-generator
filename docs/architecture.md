# PFCP Message Generator - Architecture Document

## 1. Overview

The PFCP Message Generator is a Go application that emulates an SMF node by replaying PFCP messages from a pcap file to a target UPF. It modifies session-specific identifiers (SEID, UE IP) while preserving rule IDs and other IEs.

---

## 2. System Context

```
                    ┌──────────────────┐
                    │   PCAP File      │
                    │  (PFCP capture)  │
                    └────────┬─────────┘
                             │ reads
                             ▼
┌─────────────────────────────────────────────────────┐
│              PFCP Generator Tool                    │
│                                                     │
│  1. Parse pcap → extract PFCP requests              │
│  2. Modify identifiers (SEID, UE IP, Seq#)          │
│  3. Send to UPF via UDP                             │
│  4. Receive & process UPF responses                 │
│  5. Track sessions & collect statistics             │
└───────────────────────┬─────────────────────────────┘
                        │ UDP port 8805
                        ▼
                 ┌──────────────┐
                 │   Target UPF │
                 └──────────────┘
```

---

## 3. Component Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     PFCP Generator Tool                      │
├──────────────────────────────────────────────────────────────┤
│  CLI Interface (cobra)                                       │
│  - Parse flags and arguments                                 │
│  - Load configuration                                        │
│  - Orchestrate execution                                     │
├──────────────────────────────────────────────────────────────┤
│  Config Manager          │  Statistics Collector             │
│  - YAML loading (viper)  │  - Per-message-type counters      │
│  - CLI flag overrides    │  - Response time tracking          │
│  - Validation            │  - Periodic reporting              │
├──────────────────────────┴───────────────────────────────────┤
│  PCAP Parser (gopacket)  →  PFCP Decoder (wmnsk/go-pfcp)     │
│  - Read pcap/pcapng/SLL  │  - Parse PFCP from raw bytes      │
│  - Filter UDP:8805       │  - Identify message types          │
│  - Extract payloads      │  - Decode IEs                      │
├──────────────────────────────────────────────────────────────┤
│  Session Manager                                             │
│  - SEID Allocator (sequential/random)                        │
│  - UE IP Pool (IPv4 CIDR / IPv6 prefix)                      │
│  - Session state tracking (local SEID ↔ remote SEID ↔ UE IP) │
│  - Original → new session mapping                            │
├──────────────────────────────────────────────────────────────┤
│  PFCP Message Modifier                                       │
│  - Replace F-SEID IE (SEID + SMF IP)                         │
│  - Replace UE IP Address IE (strip IPv6 if configured)       │
│  - Update PFCP header SEID                                   │
│  - Update sequence number                                    │
│  - Preserve PDR/FAR/QER/URR/BAR IDs                          │
│  - Preserve F-TEID and all other IEs                         │
├──────────────────────────────────────────────────────────────┤
│  Network Layer                                               │
│  - UDP Client Pool (multi-source-port, round-robin)          │
│  - Response Receiver (multi-conn async listener)             │
│  - Transaction Tracker (seq# → pending, port-aware retx)    │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 Stress Test Mode Architecture

```
                         ┌──────────────────────────────────────────┐
                         │            Stress Controller              │
                         │                                          │
                         │  ┌──────────┐    ┌───────────────────┐  │
                         │  │  Timer    │    │  Session Semaphore │  │
                         │  │ (N hrs)   │    │   (cap = 10,000)  │  │
                         │  └────┬─────┘    └────────┬──────────┘  │
                         │       │                   │              │
                         │  ┌────▼───────────────────▼──────────┐  │
                         │  │         Feeder Goroutine           │  │
                         │  │  Enqueue templates round-robin     │  │
                         │  │  Block on semaphore when full      │  │
                         │  └────────────┬──────────────────────┘  │
                         └───────────────┼──────────────────────────┘
                                         │ workCh
              ┌──────────────────────────┼──────────────────────────┐
              │                          │                          │
        ┌─────▼─────┐             ┌─────▼─────┐             ┌─────▼─────┐
        │  Worker 0  │             │  Worker 1  │    ...      │ Worker N-1│
        │            │             │            │             │           │
        │ for tmpl   │             │ for tmpl   │             │ for tmpl  │
        │  in workCh:│             │  in workCh:│             │ in workCh:│
        │   rate.Wait│             │   rate.Wait│             │  rate.Wait│
        │   send()   │             │   send()   │             │  send()   │
        │   waitResp │             │   waitResp │             │  waitResp │
        │  <-sem     │             │  <-sem     │             │  <-sem    │
        └─────┬──────┘             └─────┬──────┘             └─────┬────┘
              │                          │                          │
              └───────────┬──────────────┘                          │
                          │   Send (lock-free)                      │
                    ┌─────▼─────────────────────────────────────────▼──┐
                    │              UDPClientPool                        │
                    │   N UDPConns (round-robin, goroutine-safe)        │
                    │   Port range: smfPort .. smfPort+N-1              │
                    └──────────┬───────────────────────────────────────┘
                               │
                    ┌──────────▼─────────────────────┐
                    │   Receiver (1 goroutine/conn)   │
                    │  ReadFromUDP → parse → msgChan  │
                    │  (buffer = 2 × targetTPS)       │
                    └──────────┬─────────────────────┘
                               │
                    ┌──────────▼──────────────────────┐
                    │   Response Handler Goroutine     │
                    │  msgChan → tracker.Resolve()     │
                    │  (64-shard map by seq num)       │
                    └──────────────────────────────────┘
```

**Performance optimizations:**

| Component | Technique | Impact |
|-----------|-----------|--------|
| UDP Send | Multi-port pool, lock-free (UDPConn goroutine-safe) | Parallel writes, RSS distribution |
| Receiver | Multi-conn fan-in, `sync.Pool` buffers, dynamic channel | Reduces GC, prevents overflow |
| Stats | `sync/atomic` counters, fixed-bucket histogram | Lock-free, constant memory |
| Transactions | 64-shard map, port-aware retransmission | 64× less contention |
| IP Pool | `[]uint32` free-list stack | O(1) alloc/release, no strings |
| SEID Alloc | `atomic.Uint64` counter + free-list | Lock-free fast path |
| Rate Limiter | Wall-clock catch-up ticker (recovers dropped ticks under goroutine load) | Reliable at 40K+ TPS |
| Sequence Counter | `atomic.Uint32` | Lock-free |
| Modifier | Vendor IE stripping (type >= 32768) | Clean messages to UPF |

**Resource budget (50K TPS, 10K sessions):**

| Resource | Value |
|----------|-------|
| Goroutines | ~10,005 |
| Memory (sessions) | ~2 MB |
| Memory (stats) | < 1 KB |
| Memory (total steady-state) | ~100 MB |
| Network bandwidth (out) | ~10 MB/s |
| UDP syscalls | ~100K/sec |

---

## 4. Directory Structure

```
pfcp-generator/
├── cmd/
│   └── pfcp-generator/
│       └── main.go                    # CLI entry point (normal + stress mode dispatch)
├── internal/
│   ├── config/
│   │   ├── config.go                  # Configuration struct incl. StressConfig
│   │   └── validator.go               # Config validation rules
│   ├── pcap/
│   │   └── parser.go                  # PCAP file reader (pcapgo, defrag, SLL fix)
│   ├── pfcp/
│   │   ├── decoder.go                 # wmnsk/go-pfcp wrapper for decoding raw bytes
│   │   ├── encoder.go                 # wmnsk/go-pfcp wrapper for encoding messages
│   │   ├── modifier.go               # IE modification (F-SEID, UE IP, vendor IE strip)
│   │   └── message_types.go          # Message type helpers and constants
│   ├── session/
│   │   ├── manager.go                 # Session lifecycle: Replay + ReplayStress
│   │   ├── grouper.go                 # Groups pcap messages into SessionTemplates
│   │   ├── ratelimiter.go            # Wall-clock catch-up rate limiter for high TPS
│   │   ├── seid_allocator.go          # Atomic counter + free-list SEID allocation
│   │   └── ip_pool.go                # Free-list stack UE IP allocation
│   ├── network/
│   │   ├── sender.go                  # Lock-free UDP client
│   │   ├── pool.go                    # Multi-source-port UDP client pool
│   │   ├── receiver.go               # Multi-conn async receiver with sync.Pool
│   │   └── transaction.go            # 64-shard tracker (port-aware retransmission)
│   └── stats/
│       ├── collector.go               # Atomic counters + fixed-bucket histogram
│       └── reporter.go               # Console/JSON statistics output
├── pkg/
│   └── types/
│       └── types.go                   # Shared types (SessionInfo, PFCPMessage, etc.)
├── test/
│   ├── mockupf/
│   │   └── main.go                   # High-performance mock UPF (sharded, multi-reader)
│   └── testdata/
│       ├── sample.pcap               # Test PCAP files
│       └── stard_trace.pcap          # Single-session lifecycle (Est+3Mod+Del)
├── dist/                              # Pre-built RHEL-compatible linux/amd64 binaries
├── docs/
│   ├── requirements.md               # Requirements document
│   ├── architecture.md               # This document
│   └── implementation.md             # Implementation guide
├── config.yaml                        # Example configuration file
├── Dockerfile                         # Multi-stage UBI 8.10 build
├── go.mod
├── go.sum
├── Makefile                           # Build, test, lint automation
└── README.md                          # Usage guide
```

---

## 5. Component Details

### 5.1 CLI Interface (`cmd/pfcp-generator/main.go`)

**Responsibility:** Entry point. Parses CLI arguments, loads configuration, wires up components, and orchestrates the replay workflow.

**Library:** `spf13/cobra` for command structure, `spf13/viper` for config binding.

**Key behaviors:**
- Loads config from YAML file (default: `config.yaml`, overridden by `--config`)
- CLI flags override YAML values
- Validates configuration before starting
- Prints startup summary
- Runs the replay pipeline
- Handles SIGINT/SIGTERM for graceful shutdown via `context.Context`

### 5.2 Config Manager (`internal/config/`)

**Responsibility:** Load, merge, and validate configuration from YAML files and CLI flags.

**Key types:**
```go
type Config struct {
    SMF         SMFConfig         `yaml:"smf"`
    UPF         UPFConfig         `yaml:"upf"`
    Session     SessionConfig     `yaml:"session"`
    Association AssociationConfig `yaml:"association"`
    Timing      TimingConfig      `yaml:"timing"`
    Input       InputConfig       `yaml:"input"`
    Logging     LoggingConfig     `yaml:"logging"`
    Stats       StatsConfig       `yaml:"stats"`
}
```

**Validation rules:**
- `smf.address` must be a valid IP
- `upf.address` must be a valid IP and reachable
- `input.pcap_file` must exist and be readable
- `session.ue_ip_pool` must be valid CIDR notation
- `session.seid_start` must be > 0
- `timing.response_timeout_ms` must be > 0

### 5.3 PCAP Parser (`internal/pcap/`)

**Responsibility:** Read pcap files, filter for PFCP packets, extract raw message bytes.

**Library:** `google/gopacket` with pcap handle.

**Key behaviors:**
- Opens pcap/pcapng files via `pcap.OpenOffline()`
- Supports standard Ethernet and Linux cooked capture (SLL/SLL2) link types
- Iterates packets using `gopacket.PacketSource`
- Filters by UDP layer with port 8805
- Extracts UDP payload (raw PFCP bytes)
- Returns ordered list of raw PFCP messages with metadata (timestamp, direction)
- Filters: only processes requests (SMF→UPF direction, determined by message type)

**Interface:**
```go
type Parser interface {
    Parse(filename string) ([]RawPFCPMessage, error)
}

type RawPFCPMessage struct {
    Data      []byte
    Timestamp time.Time
    SrcIP     net.IP
    DstIP     net.IP
    SrcPort   uint16
    DstPort   uint16
}
```

### 5.4 PFCP Decoder/Encoder (`internal/pfcp/`)

**Responsibility:** Decode raw bytes into structured PFCP messages and encode them back.

**Library:** `wmnsk/go-pfcp`

**Decoder:**
- `message.Parse(data)` to decode raw bytes
- Type-assert to specific message types
- Extract IEs for inspection and modification

**Encoder:**
- `msg.Marshal()` to serialize modified messages to bytes
- Used after modifier has updated IEs

### 5.5 PFCP Message Modifier (`internal/pfcp/modifier.go`)

**Responsibility:** Apply identifier modifications to decoded PFCP messages before sending.

**Modification rules:**
| IE | Action | Applies to |
|----|--------|-----------|
| F-SEID (Type 57) | Replace SEID + IPv4/IPv6 | Session Establishment Request |
| UE IP Address (Type 93) | Replace IPv4; strip IPv6 if configured | Create PDR → PDI |
| Header SEID | Set to remote SEID or 0 | All session-related requests |
| Header Sequence Number | Increment | All requests |
| Node ID | Optionally update | Association Setup Request |
| Vendor IEs (Type >= 32768) | Strip recursively if configured | Establishment, Modification |

**Preservation rules:**
- PDR ID, FAR ID, QER ID, URR ID, BAR ID: pass through unchanged
- F-TEID: pass through unchanged
- All other standard IEs: pass through unchanged

**Interface:**
```go
type Modifier interface {
    ModifyAssociationSetup(msg *message.AssociationSetupRequest, seqNum uint32) error
    ModifySessionEstablishment(msg *message.SessionEstablishmentRequest, session *SessionInfo, seqNum uint32) error
    ModifySessionModification(msg *message.SessionModificationRequest, session *SessionInfo, seqNum uint32) error
    ModifySessionDeletion(msg *message.SessionDeletionRequest, session *SessionInfo, seqNum uint32) error
}
```

### 5.6 Session Manager (`internal/session/`)

**Responsibility:** Manage the lifecycle of PFCP sessions, allocate identifiers, and maintain session mappings.

**Key types:**
```go
type SessionInfo struct {
    OriginalSEID uint64    // SEID from pcap (for mapping)
    LocalSEID    uint64    // Newly allocated CP SEID
    RemoteSEID   uint64    // UP SEID from UPF response
    UEIP         net.IP    // Allocated UE IP
    State        string    // "establishing", "established", "modifying", "deleting", "deleted"
    CreatedAt    time.Time
}
```

**Sub-components:**

**SEID Allocator (`seid_allocator.go`):**
- Sequential: starts from configurable base, increments by 1
- Random: generates random uint64, checks for collision
- Thread-safe with mutex
- Tracks allocated SEIDs; supports release on session deletion

**UE IP Pool (`ip_pool.go`):**
- Initialized from CIDR notation (e.g., `10.60.0.0/24`)
- Sequential allocation starting from first usable address
- Thread-safe with mutex
- Release on session deletion
- Reports exhaustion errors

**Session mapping:**
- Maps original pcap SEID → new SessionInfo
- Maps local SEID → SessionInfo (for response correlation)
- Concurrent-safe with `sync.RWMutex`

### 5.7 Network Layer (`internal/network/`)

**Responsibility:** Handle UDP communication with the UPF.

**Client Pool (`pool.go`):**
- Manages N `UDPClient` instances on sequential ports (smfPort to smfPort+N-1)
- Round-robin dispatch via `atomic.Uint64` counter
- `SendOn(portIndex, data)` for deterministic retransmission on the same port
- `Conns()` returns all connections for receiver fan-in

**Sender (`sender.go`):**
- Creates a single UDP connection to UPF address:port
- Lock-free `WriteToUDP` (Go's `UDPConn` is goroutine-safe)
- Binds to configured SMF address:port

**Receiver (`receiver.go`):**
- Listens for incoming UDP messages across N connections (one goroutine per conn)
- Fans in to a single shared channel
- `sync.Pool` for receive buffer reuse
- Parses received PFCP messages and dispatches to transaction tracker

**Transaction Tracker (`transaction.go`):**
- 64-shard map: sequence number → pending transaction
- Each transaction stores: request data, send time, retry count, response channel, **port index**
- Timeout goroutine monitors pending transactions across all shards
- Retransmits on timeout using the **same source port** as the original request
- Resolves transactions when matching response arrives

**Key types:**
```go
type UDPClientPool struct {
    clients []*UDPClient
    counter atomic.Uint64
}

type RetransmitSender interface {
    SendOn(portIndex int, data []byte) error
}

type PendingTransaction struct {
    SeqNum      uint32
    RequestData []byte
    PortIndex   int  // source port used, for retransmission
    ...
}
```

### 5.8 Statistics Collector (`internal/stats/`)

**Responsibility:** Aggregate and report operational statistics.

**Tracked metrics:**
- Messages sent per type (Association, Establishment, Modification, Deletion, Heartbeat)
- Responses received per type
- Success count (Cause = Request Accepted)
- Failure count (Cause != Request Accepted)
- Timeout count
- Retransmission count
- Active session count
- Response time per message (min, avg, max, p99)
- Overall duration
- TPS (transactions per second, current and average)

**Reporter (`reporter.go`):**
- **Normal mode:** Periodic console output at configurable interval
- **Stress mode:** Live terminal dashboard (1-second refresh) with ANSI cursor control, box-drawing table, per-message-type breakdown, TPS tracking, and comma-formatted numbers. Logs auto-redirect to file.
- Final summary on completion
- Optional JSON export to file

---

## 6. Data Flow

### 6.1 Main Replay Pipeline

```
┌──────────┐    ┌────────────┐    ┌──────────────┐    ┌──────────────┐
│  PCAP    │───>│  Decoder   │───>│  Modifier    │───>│  Sender      │
│  Parser  │    │            │    │              │    │              │
└──────────┘    └────────────┘    └──────────────┘    └──────┬───────┘
                                        ▲                     │
                                        │                     │ UDP
                                  ┌─────┴──────┐              │
                                  │  Session   │              ▼
                                  │  Manager   │       ┌──────────────┐
                                  │            │<──────│  Receiver    │
                                  └────────────┘       │  + Tracker   │
                                                       └──────────────┘
```

### 6.2 Message Processing Sequence

```
1. PCAP Parser reads next PFCP message
2. Decoder parses raw bytes → structured message
3. Based on message type:
   a. Association Setup Request:
      - Modifier updates Node ID, sequence number
      - Sender transmits to UPF
      - Tracker waits for response
      - Validate response (must succeed to continue)
   b. Session Establishment Request:
      - Session Manager allocates SEID + UE IP
      - Session Manager creates original→new mapping
      - Modifier replaces F-SEID, UE IP, header SEID=0, seq#
      - Sender transmits to UPF
      - Tracker waits for response
      - Session Manager extracts remote SEID from response
   c. Session Modification Request:
      - Session Manager looks up session by original SEID
      - Modifier updates header SEID to remote SEID, seq#
      - Sender transmits to UPF
      - Tracker waits for response
   d. Session Deletion Request:
      - Session Manager looks up session by original SEID
      - Modifier updates header SEID to remote SEID, seq#
      - Sender transmits to UPF
      - Tracker waits for response
      - Session Manager releases SEID + UE IP
4. Statistics Collector records outcome
5. Repeat from step 1
```

---

## 7. Key Design Decisions

| # | Decision | Rationale |
|---|---------|-----------|
| 1 | Use `wmnsk/go-pfcp` for PFCP protocol handling | Mature, well-maintained Go library with full 3GPP TS 29.244 support |
| 2 | Use `google/gopacket` for PCAP parsing | De facto standard for packet capture in Go, supports pcap and pcapng |
| 3 | Clean architecture with separated concerns | Each component has a single responsibility, enabling independent testing and modification |
| 4 | Interface-based design for external dependencies | Enables unit testing with mocks (network, PCAP, etc.) |
| 5 | Configuration via YAML with CLI overrides | YAML for repeatable configurations; CLI flags for quick adjustments |
| 6 | Sequential message processing (not parallel) | Preserves pcap message ordering; simplifies session state management; sufficient for testing |
| 7 | Single association per run | Simplifies state management; matches typical SMF behavior |
| 8 | Trust pcap content (no 3GPP validation) | Tool is a replayer, not a validator; reduces complexity |
| 9 | Use `context.Context` throughout | Enables clean cancellation and graceful shutdown |
| 10 | `internal/` packages for non-exported code | Follows Go convention; prevents external import of implementation details |

---

## 8. Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `github.com/wmnsk/go-pfcp` | v0.0.24 | PFCP message encoding/decoding |
| `github.com/google/gopacket` | v1.1.19 | PCAP file parsing |
| `github.com/spf13/cobra` | v1.8.0 | CLI framework |
| `github.com/spf13/viper` | v1.18.2 | Configuration management |
| `gopkg.in/yaml.v3` | v3.0.1 | YAML parsing |
| `github.com/sirupsen/logrus` | v1.9.3 | Structured logging |
| `github.com/stretchr/testify` | v1.8.4 | Test assertions |

---

## 9. Concurrency Model

### 9.1 Replay Mode (Default)

```
Main Goroutine
│
├── PCAP Parser (synchronous, runs on main goroutine)
│
├── Message Processing Loop (main goroutine)
│   ├── Decode → Modify → Send (sequential per message)
│   └── Wait for response (with timeout)
│
├── Receiver Goroutines (1 per source port)
│   └── Listen on UDP sockets, fan-in to shared msgChan
│
├── Transaction Timeout Monitor Goroutine
│   └── Periodically checks for timed-out transactions (64 shards)
│
└── Stats Reporter Goroutine (optional)
    └── Periodically prints statistics
```

### 9.2 Stress Test Mode

```
Main Goroutine
│
├── PCAP Parser (synchronous, startup only)
│
├── Session Grouper (startup only)
│   └── Groups pcap messages into SessionTemplates via BuildReplayPlan()
│
├── Feeder Goroutine
│   ├── Enqueues session templates round-robin onto workCh
│   ├── Blocks on semaphore when active sessions reach cap (e.g., 10,000)
│   └── Stops on context cancellation or duration timer
│
├── Worker Goroutines (N = ActiveSessions from config)
│   ├── Consume templates from workCh
│   ├── For each template message:
│   │   ├── rate.Wait() — blocks until rate limiter grants a token
│   │   ├── Modify message (SEID, UE IP, seq#)
│   │   ├── Send via UDPClientPool (round-robin source port)
│   │   └── Wait for response via 64-shard transaction tracker
│   └── Release semaphore slot on session completion
│
├── Rate Limiter Goroutine
│   └── Wall-clock catch-up: computes expected tokens from elapsed time, recovers missed ticks
│
├── Receiver Goroutines (1 per source port)
│   ├── ReadFromUDP with sync.Pool buffer reuse
│   └── Fan-in to shared msgChan (buffer = 2 × targetTPS)
│
├── Response Handler Goroutine
│   └── Drains msgChan → tracker.Resolve() (sharded by seq num)
│
├── Transaction Timeout Monitor Goroutine
│   └── Scans 64 shards for timed-out transactions
│
└── Progress Logger Goroutine
    └── Prints TPS, active sessions, totals every 10 seconds
```

### 9.3 Synchronization

| Component | Replay Mode | Stress Mode |
|-----------|-------------|-------------|
| SEID Allocator | `sync.Mutex` (free-list) | `atomic.Uint64` (fast path) + `sync.Mutex` (free-list reuse) |
| UE IP Pool | `sync.Mutex` (free-list stack) | Same |
| Session Manager | `sync.RWMutex` | Same |
| Transaction Tracker | 64-shard `sync.Mutex` | Same |
| Statistics Collector | `sync/atomic` counters | Same |
| Response Times | Fixed-bucket histogram (`atomic.Uint64` per bucket) | Same |
| Sequence Counter | `atomic.Uint32` with CAS | Same |
| UDP Send | Multi-port pool, lock-free (UDPConn goroutine-safe) | Same |

All goroutines respect `context.Context` for shutdown.

---

## 10. Error Handling Strategy

| Error Type | Handling |
|-----------|---------|
| PCAP file not found / unreadable | Fatal: exit with clear error message |
| Invalid configuration | Fatal: exit with validation errors |
| PFCP decode failure (single message) | Warn: log and skip to next message |
| Association Setup failure | Fatal if enabled: cannot proceed without association (configurable) |
| Session Establishment failure | Error: log, skip session, continue with next |
| Session Modification/Deletion failure | Error: log, continue with next message |
| Response timeout (after retries) | Error: log timeout, continue with next message |
| UPF unreachable | Fatal: exit after connection failure |
| IP pool exhausted | Error: log, skip session establishment |
| SEID collision (random mode) | Retry allocation (internal, transparent) |
