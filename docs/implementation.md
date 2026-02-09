# PFCP Message Generator - Implementation Guide

## 1. Overview

This document provides detailed implementation specifications for each component of the PFCP Message Generator. It covers data structures, algorithms, configuration schema, error handling, and testing strategy.

---

## 2. Implementation Order

Modules should be implemented in dependency order:

```
1. internal/config       ← no internal dependencies
2. internal/session/ip_pool      ← no internal dependencies
3. internal/session/seid_allocator  ← no internal dependencies
4. pkg/types             ← no internal dependencies
5. internal/pfcp/decoder ← depends on pkg/types
6. internal/pfcp/encoder ← depends on pkg/types
7. internal/pfcp/modifier ← depends on session, pfcp
8. internal/pcap         ← depends on pfcp/decoder
9. internal/network      ← depends on pfcp, pkg/types
10. internal/session/manager ← depends on seid_allocator, ip_pool, pkg/types
11. internal/stats        ← depends on pkg/types
12. cmd/pfcp-generator    ← depends on all above
```

---

## 3. SEID Management Strategy

### 3.1 Local SEID (CP-assigned)

The local SEID is the identifier that the SMF (our tool) assigns to each session. The UPF uses this SEID in the PFCP header when sending messages back to the SMF.

**Sequential allocation (default):**
```go
type SEIDAllocator struct {
    strategy  string
    nextSEID  uint64
    usedSEIDs map[uint64]bool
    mu        sync.Mutex
}

func NewSEIDAllocator(strategy string, startSEID uint64) *SEIDAllocator {
    return &SEIDAllocator{
        strategy:  strategy,
        nextSEID:  startSEID,
        usedSEIDs: make(map[uint64]bool),
    }
}

func (s *SEIDAllocator) Allocate() (uint64, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    switch s.strategy {
    case "sequential":
        for {
            if s.nextSEID == 0 {
                s.nextSEID = 1 // SEID 0 is reserved
            }
            seid := s.nextSEID
            s.nextSEID++
            if !s.usedSEIDs[seid] {
                s.usedSEIDs[seid] = true
                return seid, nil
            }
        }
    case "random":
        for attempts := 0; attempts < 1000; attempts++ {
            seid := rand.Uint64()
            if seid == 0 || s.usedSEIDs[seid] {
                continue
            }
            s.usedSEIDs[seid] = true
            return seid, nil
        }
        return 0, fmt.Errorf("failed to allocate random SEID after 1000 attempts")
    default:
        return 0, fmt.Errorf("unknown SEID strategy: %s", s.strategy)
    }
}

func (s *SEIDAllocator) Release(seid uint64) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.usedSEIDs, seid)
}
```

**Key rules:**
- SEID 0 is reserved (used in Session Establishment Request header to mean "no SEID yet")
- Sequential starts from configurable base (default: 1)
- Thread-safe: all operations protected by mutex
- Release on session deletion to allow reuse in long-running scenarios

### 3.2 Remote SEID (UP-assigned)

The remote SEID is provided by the UPF in the Session Establishment Response inside the F-SEID IE.

**Extraction from response:**
```go
func extractRemoteSEID(resp *message.SessionEstablishmentResponse) (uint64, error) {
    if resp.UPFSEID == nil {
        return 0, fmt.Errorf("no UP F-SEID in Session Establishment Response")
    }
    fseid, err := resp.UPFSEID.FSEID()
    if err != nil {
        return 0, fmt.Errorf("failed to parse UP F-SEID: %w", err)
    }
    return fseid.SEID, nil
}
```

**Usage in subsequent messages:**
- Session Modification Request: header SEID = remote SEID
- Session Deletion Request: header SEID = remote SEID

### 3.3 Original-to-New Session Mapping

The pcap contains sessions with original SEIDs. We need to map them to new sessions:

```go
type SessionMapping struct {
    // originalSEID → SessionInfo
    byOriginalSEID map[uint64]*SessionInfo
    // localSEID → SessionInfo (for response correlation)
    byLocalSEID    map[uint64]*SessionInfo
    mu             sync.RWMutex
}
```

When processing a Session Establishment Request from the pcap:
1. Extract the original F-SEID from the pcap message to get the original SEID
2. Allocate a new local SEID
3. Create a mapping: `originalSEID → {localSEID, ueIP, ...}`

When processing subsequent messages (Modification, Deletion):
1. Extract the header SEID from the pcap message (this is the remote SEID the original SMF used)
2. Look up the corresponding session by the original remote SEID
3. Replace with the actual remote SEID obtained from the UPF response

---

## 4. UE IP Pool Implementation

### 4.1 IPv4 Pool

```go
type UEIPPool struct {
    cidr      *net.IPNet
    nextIP    net.IP
    allocated map[string]bool
    mu        sync.Mutex
}

func NewUEIPPool(cidr string) (*UEIPPool, error) {
    _, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
    }

    // Start from first usable address (network + 1)
    firstIP := make(net.IP, len(ipnet.IP))
    copy(firstIP, ipnet.IP)
    incrementIP(firstIP)

    return &UEIPPool{
        cidr:      ipnet,
        nextIP:    firstIP,
        allocated: make(map[string]bool),
    }, nil
}

func (p *UEIPPool) Allocate() (net.IP, error) {
    p.mu.Lock()
    defer p.mu.Unlock()

    startIP := make(net.IP, len(p.nextIP))
    copy(startIP, p.nextIP)

    for {
        if !p.cidr.Contains(p.nextIP) {
            // Wrap around to start of range
            copy(p.nextIP, p.cidr.IP)
            incrementIP(p.nextIP)
        }

        ipStr := p.nextIP.String()
        if !p.allocated[ipStr] {
            p.allocated[ipStr] = true
            result := make(net.IP, len(p.nextIP))
            copy(result, p.nextIP)
            incrementIP(p.nextIP)
            return result, nil
        }

        incrementIP(p.nextIP)

        if p.nextIP.Equal(startIP) {
            return nil, fmt.Errorf("UE IP pool exhausted (all %d addresses allocated)", len(p.allocated))
        }
    }
}

func (p *UEIPPool) Release(ip net.IP) {
    p.mu.Lock()
    defer p.mu.Unlock()
    delete(p.allocated, ip.String())
}

func (p *UEIPPool) Available() int {
    p.mu.Lock()
    defer p.mu.Unlock()
    // Calculate total IPs in CIDR minus allocated
    ones, bits := p.cidr.Mask.Size()
    total := 1 << (bits - ones)
    return total - len(p.allocated) - 2 // subtract network and broadcast
}

func incrementIP(ip net.IP) {
    for i := len(ip) - 1; i >= 0; i-- {
        ip[i]++
        if ip[i] > 0 {
            break
        }
    }
}
```

### 4.2 IPv6 Stripping (Configurable)

When `session.strip_ipv6` is enabled (default: true), the modifier will:
1. Remove the IPv6 address from UE IP Address IEs
2. Clear the V6 flag, keeping only V4
3. This ensures all sessions use IPv4-only addressing from the configured pool

This is controlled by the `session.strip_ipv6` config flag.

---

## 5. IE Modification Rules

### 5.1 IEs That MUST Be Modified

#### 5.1.1 F-SEID IE (Type 57)

**Location:** Top-level IE in Session Establishment Request

**Modification:**
```go
func modifyFSEID(msg *message.SessionEstablishmentRequest, newSEID uint64, smfIP string) {
    if msg.CPFSEID != nil {
        // Create new F-SEID with allocated SEID and configured SMF IP
        msg.CPFSEID = ie.NewFSEID(newSEID, smfIP, "")
    }
}
```

**What changes:**
- `SEID` field → newly allocated local SEID
- `IPv4 Address` → configured SMF address (optional, preserves original if not configured)
- `IPv6 Address` → configured SMF IPv6 address (optional)

#### 5.1.2 UE IP Address IE (Type 93)

**Location:** Nested inside Create PDR → PDI (Packet Detection Information)

**Modification:**
```go
func modifyUEIPInPDRs(createPDRs []*ie.IE, newUEIP net.IP) error {
    for _, pdr := range createPDRs {
        if pdr == nil {
            continue
        }
        // Navigate to PDI within Create PDR
        pdis, err := pdr.PDI()
        if err != nil {
            continue // PDR may not have PDI
        }

        // Rebuild PDI with modified UE IP
        newChildIEs := make([]*ie.IE, 0, len(pdis))
        for _, childIE := range pdis {
            if childIE.Type == ie.UEIPAddress {
                // Determine if IPv4 or IPv6 based on original
                ueIPFields, err := childIE.UEIPAddress()
                if err != nil {
                    newChildIEs = append(newChildIEs, childIE) // preserve on error
                    continue
                }
                if ueIPFields.Flags&0x02 != 0 { // V4 flag
                    newChildIEs = append(newChildIEs, ie.NewUEIPAddress(
                        ueIPFields.Flags, newUEIP.String(), "", 0, 0,
                    ))
                }
                // Handle IPv6 similarly if needed
            } else {
                newChildIEs = append(newChildIEs, childIE)
            }
        }

        // Rebuild the PDI IE with updated children
        // (Implementation depends on go-pfcp IE construction API)
    }
    return nil
}
```

**What changes:**
- `IPv4 Address` or `IPv6 Address` → allocated UE IP from pool
- Flags preserved (V4/V6 match the original)

#### 5.1.3 SEID in PFCP Header

**Applies to:** All session-related messages (S=1)

| Message Type | Header SEID Value |
|-------------|------------------|
| Session Establishment Request | 0 (no remote SEID yet) |
| Session Modification Request | Remote SEID (from UPF's Establishment Response) |
| Session Deletion Request | Remote SEID (from UPF's Establishment Response) |

**Implementation:** Set via the message constructor or by direct field assignment before marshaling.

#### 5.1.4 Sequence Number in PFCP Header

**Applies to:** All request messages

```go
type SequenceCounter struct {
    current uint32
    mu      sync.Mutex
}

func (s *SequenceCounter) Next() uint32 {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.current++
    if s.current > 0xFFFFFF { // 24-bit max
        s.current = 1
    }
    return s.current
}
```

### 5.2 IEs That MUST Be Preserved (DO NOT MODIFY)

| IE | Type | Reason |
|----|------|--------|
| PDR ID | 56 | Already unique per session in pcap |
| FAR ID | 108 | Already unique per session in pcap |
| QER ID | 109 | Already unique per session in pcap |
| URR ID | 81 | Already unique per session in pcap |
| BAR ID | 88 | Already unique per session in pcap |
| F-TEID | 21 | Allocated by UPF, not SMF |
| Network Instance | 22 | Network config, not session-specific |
| QFI | 124 | QoS config, not session-specific |
| Apply Action | 44 | Forwarding rules, preserve from pcap |
| Outer Header Creation | 84 | GTP-U tunnel info, preserve from pcap |
| Precedence | 29 | Rule priority, preserve from pcap |
| All other IEs | - | Only modify explicitly listed IEs |

---

## 6. Message Processing Flow

### 6.1 Overall Flow

```
START
  │
  ▼
Parse PCAP file
  │
  ▼
Extract PFCP request messages (ordered)
  │
  ▼
For each message:
  │
  ├─ Association Setup Request ──────────────────────┐
  │   1. Update Node ID (optional)                   │
  │   2. Update sequence number                      │
  │   3. Send to UPF                                 │
  │   4. Wait for response                           │
  │   5. If FAILED → ABORT (cannot continue)         │
  │   6. If SUCCESS → continue                       │
  │                                                  │
  ├─ Session Establishment Request ──────────────────┤
  │   1. Extract original F-SEID (for mapping)       │
  │   2. Allocate new local SEID                     │
  │   3. Allocate UE IP from pool                    │
  │   4. Replace F-SEID IE                           │
  │   5. Replace UE IP Address in PDI                │
  │   6. Set header SEID = 0                         │
  │   7. Update sequence number                      │
  │   8. Send to UPF                                 │
  │   9. Wait for response                           │
  │  10. Extract remote SEID from response           │
  │  11. Store mapping: original ↔ local ↔ remote    │
  │  12. Record statistics                           │
  │                                                  │
  ├─ Session Modification Request ───────────────────┤
  │   1. Extract header SEID from pcap (original     │
  │      remote SEID used by original SMF)           │
  │   2. Look up session by original remote SEID     │
  │   3. Set header SEID = actual remote SEID        │
  │   4. Update sequence number                      │
  │   5. Send to UPF                                 │
  │   6. Wait for response                           │
  │   7. Record statistics                           │
  │                                                  │
  ├─ Session Deletion Request ───────────────────────┤
  │   1. Same as Modification (steps 1-4)            │
  │   2. Send to UPF                                 │
  │   3. Wait for response                           │
  │   4. Release local SEID + UE IP                  │
  │   5. Record statistics                           │
  │                                                  │
  ├─ Heartbeat Request ─────────────────────────────┤
  │   1. Update sequence number                      │
  │   2. Send to UPF                                 │
  │   3. Wait for response                           │
  │                                                  │
  └─ Unknown/Other ─────────────────────────────────┤
      1. Log warning, skip                           │
                                                     │
  Apply inter-message delay (if configured)          │
  │                                                  │
  ▼                                                  │
Next message ◄───────────────────────────────────────┘
  │
  ▼
If cleanup_on_exit enabled AND active sessions remain:
  │  → Send Session Deletion for each active session
  │
  ▼
Print final statistics
  │
  ▼
END

Note: Association Setup is skipped if association.enabled=false.
Pcap MUST contain at least one Session Establishment Request or tool exits with error.
```

### 6.2 Session Mapping Detail

The pcap contains messages from an original SMF with its own SEIDs. We need to map from the original session context to our new session context.

**Establishment phase:**
```
PCAP message:
  - F-SEID IE contains original CP SEID (e.g., 1001)
  - Header SEID = 0

Our message:
  - F-SEID IE contains new local SEID (e.g., 1)
  - Header SEID = 0

UPF response:
  - F-SEID IE contains remote SEID (e.g., 5001)

Mapping stored:
  original_cp_seid=1001 → local_seid=1, remote_seid=5001, ue_ip=10.60.0.1
```

**Subsequent messages (Modification/Deletion):**
```
PCAP message:
  - Header SEID = original remote SEID the original SMF received
    (this was the UPF's SEID for the original session)

We need to:
  1. Find which original session this belongs to
  2. Replace header SEID with OUR remote SEID from OUR UPF
```

**Challenge:** The pcap's Modification/Deletion messages have the *original UPF's remote SEID* in the header. We need a second mapping: `original_remote_seid → session`. This is built by also tracking what remote SEID appeared in the pcap's Establishment Response (if responses are present in the pcap) or by tracking the order of sessions.

**Approach:** Track sessions by order of appearance in the pcap. The Nth Establishment Request maps to the Nth session we create. Subsequent Modification/Deletion messages reference sessions by the remote SEID from the pcap, which we map using the captured pcap response's F-SEID.

---

## 7. Configuration Schema

### 7.1 YAML Configuration File

```yaml
# SMF (this tool) configuration
smf:
  address: "192.168.1.10"       # Local IP to bind for PFCP
  port: 8805                     # Local PFCP port (default: 8805)
  node_id: ""                    # Node ID FQDN (optional, auto-generated if empty)

# Target UPF configuration
upf:
  address: "192.168.1.20"       # UPF IP address
  port: 8805                     # UPF PFCP port (default: 8805)

# Association configuration
association:
  enabled: true                  # Enable PFCP Association Setup (default: true)

# Session configuration
session:
  seid_start: 1                  # Starting SEID value (default: 1)
  seid_strategy: "sequential"    # "sequential" or "random" (default: "sequential")
  ue_ip_pool: "10.60.0.0/24"    # UE IPv4 address pool (CIDR notation)
  strip_ipv6: true               # Strip IPv6 from UE IP, force IPv4-only (default: true)
  cleanup_on_exit: false         # Delete all sessions on shutdown (default: false)

# Timing configuration
timing:
  message_interval_ms: 100       # Delay between messages in ms (0 = no delay)
  response_timeout_ms: 5000      # Timeout waiting for UPF response (default: 5000)
  max_retries: 3                 # Max retransmission attempts (default: 3)

# Input configuration
input:
  pcap_file: "capture.pcap"     # Path to input PCAP file

# Logging configuration
logging:
  level: "info"                  # "debug", "info", "warn", "error" (default: "info")
  file: ""                       # Log file path (empty = no file logging)
  console: true                  # Log to stdout (default: true)

# Statistics configuration
stats:
  enabled: true                  # Enable statistics collection (default: true)
  report_interval_sec: 10        # Periodic report interval (0 = only final report)
  export_file: ""                # Export stats to JSON file (empty = no export)
```

### 7.2 Go Config Struct

```go
type Config struct {
    SMF         SMFConfig         `yaml:"smf"         mapstructure:"smf"`
    UPF         UPFConfig         `yaml:"upf"         mapstructure:"upf"`
    Association AssociationConfig `yaml:"association" mapstructure:"association"`
    Session     SessionConfig     `yaml:"session"     mapstructure:"session"`
    Timing      TimingConfig      `yaml:"timing"      mapstructure:"timing"`
    Input       InputConfig       `yaml:"input"       mapstructure:"input"`
    Logging     LoggingConfig     `yaml:"logging"     mapstructure:"logging"`
    Stats       StatsConfig       `yaml:"stats"       mapstructure:"stats"`
}

type AssociationConfig struct {
    Enabled bool `yaml:"enabled" mapstructure:"enabled"`
}

type SMFConfig struct {
    Address string `yaml:"address" mapstructure:"address"`
    Port    int    `yaml:"port"    mapstructure:"port"`
    NodeID  string `yaml:"node_id" mapstructure:"node_id"`
}

type UPFConfig struct {
    Address string `yaml:"address" mapstructure:"address"`
    Port    int    `yaml:"port"    mapstructure:"port"`
}

type SessionConfig struct {
    SEIDStart     uint64 `yaml:"seid_start"      mapstructure:"seid_start"`
    SEIDStrategy  string `yaml:"seid_strategy"   mapstructure:"seid_strategy"`
    UEIPPool      string `yaml:"ue_ip_pool"      mapstructure:"ue_ip_pool"`
    StripIPv6     bool   `yaml:"strip_ipv6"      mapstructure:"strip_ipv6"`
    CleanupOnExit bool   `yaml:"cleanup_on_exit" mapstructure:"cleanup_on_exit"`
}

type TimingConfig struct {
    MessageIntervalMs int `yaml:"message_interval_ms" mapstructure:"message_interval_ms"`
    ResponseTimeoutMs int `yaml:"response_timeout_ms" mapstructure:"response_timeout_ms"`
    MaxRetries        int `yaml:"max_retries"         mapstructure:"max_retries"`
}

type InputConfig struct {
    PcapFile string `yaml:"pcap_file" mapstructure:"pcap_file"`
}

type LoggingConfig struct {
    Level   string `yaml:"level"   mapstructure:"level"`
    File    string `yaml:"file"    mapstructure:"file"`
    Console bool   `yaml:"console" mapstructure:"console"`
}

type StatsConfig struct {
    Enabled           bool   `yaml:"enabled"             mapstructure:"enabled"`
    ReportIntervalSec int    `yaml:"report_interval_sec" mapstructure:"report_interval_sec"`
    ExportFile        string `yaml:"export_file"         mapstructure:"export_file"`
}
```

### 7.3 CLI Flags (Override YAML)

```
--config string          Configuration file path (default "config.yaml")
--pcap string            Input PCAP file path
--smf-ip string          Local SMF IP address
--upf-ip string          Target UPF IP address
--upf-port int           Target UPF port (default 8805)
--ue-pool string         UE IPv4 address pool (CIDR)
--seid-start uint        Starting SEID value
--seid-strategy string   SEID allocation strategy (sequential|random)
--message-interval duration  Delay between messages (e.g., 100ms)
--timeout duration       Response timeout (e.g., 5s)
--max-retries int        Max retransmission attempts
--log-level string       Log level (debug|info|warn|error)
--dry-run               Parse and modify only, do not send
--cleanup               Delete all sessions on exit
--no-association        Disable PFCP Association Setup
--strip-ipv6            Strip IPv6 from UE IP Address IEs (default: true)
--stats-only            Show pcap statistics only, do not replay
```

### 7.4 Validation Rules

```go
func (c *Config) Validate() error {
    var errs []string

    // SMF address must be valid IP
    if net.ParseIP(c.SMF.Address) == nil {
        errs = append(errs, "smf.address must be a valid IP address")
    }

    // UPF address must be valid IP
    if net.ParseIP(c.UPF.Address) == nil {
        errs = append(errs, "upf.address must be a valid IP address")
    }

    // PCAP file must exist
    if _, err := os.Stat(c.Input.PcapFile); os.IsNotExist(err) {
        errs = append(errs, fmt.Sprintf("pcap file not found: %s", c.Input.PcapFile))
    }

    // UE IP pool must be valid CIDR
    if _, _, err := net.ParseCIDR(c.Session.UEIPPool); err != nil {
        errs = append(errs, fmt.Sprintf("invalid UE IP pool CIDR: %s", c.Session.UEIPPool))
    }

    // SEID start must be > 0
    if c.Session.SEIDStart == 0 {
        errs = append(errs, "session.seid_start must be > 0")
    }

    // SEID strategy must be known
    if c.Session.SEIDStrategy != "sequential" && c.Session.SEIDStrategy != "random" {
        errs = append(errs, "session.seid_strategy must be 'sequential' or 'random'")
    }

    // Response timeout must be positive
    if c.Timing.ResponseTimeoutMs <= 0 {
        errs = append(errs, "timing.response_timeout_ms must be > 0")
    }

    if len(errs) > 0 {
        return fmt.Errorf("configuration errors:\n  - %s", strings.Join(errs, "\n  - "))
    }
    return nil
}
```

---

## 8. Error Handling

### 8.1 Error Categories

| Category | Severity | Action |
|---------|----------|--------|
| Configuration error | Fatal | Print error, exit code 1 |
| PCAP file error | Fatal | Print error, exit code 1 |
| Association failure (when enabled) | Fatal | Print error, exit code 2 |
| No Establishment in pcap | Fatal | Print error, exit code 1 |
| UPF unreachable | Fatal | Print error, exit code 3 |
| Single message decode failure | Warning | Log, skip message, continue |
| Session Establishment failure | Error | Log, skip session, continue |
| Session Modification/Deletion failure | Error | Log, continue |
| Response timeout (after retries) | Error | Log, continue |
| IP pool exhaustion | Error | Log, skip session establishment |

### 8.2 Graceful Shutdown

```go
func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle SIGINT/SIGTERM
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        sig := <-sigCh
        log.Infof("Received signal %v, shutting down...", sig)
        cancel()
    }()

    // Run replay with context
    if err := runReplay(ctx, cfg); err != nil {
        if ctx.Err() != nil {
            log.Info("Shutdown complete")
        } else {
            log.Fatalf("Replay failed: %v", err)
        }
    }
}
```

**Shutdown sequence:**
1. Cancel context → stops message processing loop
2. Wait for pending transactions to complete or timeout
3. Optionally send Session Deletion for active sessions (if `--cleanup`)
4. Close UDP connection
5. Print final statistics
6. Exit

### 8.3 Retransmission Logic

```go
func (t *TransactionTracker) handleTimeout(seqNum uint32) {
    t.mu.Lock()
    tx, exists := t.pending[seqNum]
    if !exists {
        t.mu.Unlock()
        return
    }

    if tx.retryCount < t.maxRetries {
        tx.retryCount++
        t.mu.Unlock()

        log.Warnf("Timeout for seq=%d, retransmitting (attempt %d/%d)",
            seqNum, tx.retryCount, t.maxRetries)

        // Resend same message (same sequence number per 3GPP)
        t.sender.Send(tx.requestData)
        // Reset timeout timer
        t.resetTimer(seqNum)
    } else {
        t.mu.Unlock()

        log.Errorf("Transaction seq=%d failed after %d retries", seqNum, t.maxRetries)
        tx.resultCh <- TransactionResult{
            SeqNum: seqNum,
            Error:  fmt.Errorf("timeout after %d retries", t.maxRetries),
        }
        t.remove(seqNum)
    }
}
```

---

## 9. Statistics Collection

### 9.1 Metrics Structure

```go
type Statistics struct {
    StartTime time.Time
    EndTime   time.Time

    // Per message type counters
    MessagesSent     map[string]uint64 // key: message type name
    ResponsesRecv    map[string]uint64
    SuccessCount     map[string]uint64 // Cause = RequestAccepted
    FailureCount     map[string]uint64 // Cause != RequestAccepted
    TimeoutCount     map[string]uint64
    RetransmitCount  map[string]uint64

    // Session counters
    SessionsEstablished uint64
    SessionsModified    uint64
    SessionsDeleted     uint64
    SessionsFailed      uint64
    ActiveSessions      uint64

    // Response times (nanoseconds)
    ResponseTimes []time.Duration // for computing min/avg/max/p99

    mu sync.Mutex
}
```

### 9.2 Periodic Report Format

```
=== PFCP Generator Statistics (elapsed: 30s) ===
Messages:
  Association Setup:  sent=1   recv=1   success=1  fail=0  timeout=0
  Session Establish:  sent=25  recv=24  success=24 fail=0  timeout=1
  Session Modify:     sent=20  recv=20  success=20 fail=0  timeout=0
  Session Delete:     sent=15  recv=15  success=15 fail=0  timeout=0
  Heartbeat:          sent=3   recv=3   success=3  fail=0  timeout=0
Sessions:
  Established: 24  |  Active: 9  |  Deleted: 15  |  Failed: 1
Response Times:
  Min: 1.2ms  |  Avg: 3.5ms  |  Max: 15.2ms  |  P99: 12.1ms
Throughput:
  2.1 msg/s  |  Retransmissions: 2
================================================
```

### 9.3 JSON Export Format

```json
{
  "start_time": "2024-01-15T10:30:00Z",
  "end_time": "2024-01-15T10:30:15Z",
  "duration_sec": 15.2,
  "messages": {
    "association_setup": {"sent": 1, "received": 1, "success": 1, "failed": 0, "timeout": 0},
    "session_establishment": {"sent": 50, "received": 50, "success": 50, "failed": 0, "timeout": 0},
    "session_modification": {"sent": 30, "received": 30, "success": 30, "failed": 0, "timeout": 0},
    "session_deletion": {"sent": 50, "received": 50, "success": 50, "failed": 0, "timeout": 0},
    "heartbeat": {"sent": 2, "received": 2, "success": 2, "failed": 0, "timeout": 0}
  },
  "sessions": {
    "established": 50,
    "active": 0,
    "deleted": 50,
    "failed": 0
  },
  "response_times_ms": {
    "min": 1.2,
    "avg": 3.5,
    "max": 15.2,
    "p99": 12.1
  },
  "throughput_msg_per_sec": 9.9,
  "retransmissions": 0
}
```

---

## 10. Testing Strategy

### 10.1 Unit Tests

Each module has its own test file following Go conventions (`_test.go` in same package).

#### SEID Allocator Tests (`internal/session/seid_allocator_test.go`)
```
- TestSEIDAllocator_Sequential_StartsFromBase
- TestSEIDAllocator_Sequential_Increments
- TestSEIDAllocator_Sequential_SkipsZero
- TestSEIDAllocator_Random_NeverZero
- TestSEIDAllocator_Random_NoDuplicates
- TestSEIDAllocator_Release_AllowsReuse
- TestSEIDAllocator_ConcurrentAccess
```

#### UE IP Pool Tests (`internal/session/ip_pool_test.go`)
```
- TestUEIPPool_NewFromCIDR
- TestUEIPPool_InvalidCIDR
- TestUEIPPool_Allocate_Sequential
- TestUEIPPool_Allocate_SkipsNetworkAddress
- TestUEIPPool_Exhaustion
- TestUEIPPool_Release_AllowsReallocation
- TestUEIPPool_ConcurrentAccess
- TestUEIPPool_Available_Count
```

#### Config Validation Tests (`internal/config/validator_test.go`)
```
- TestConfig_ValidConfig
- TestConfig_InvalidSMFAddress
- TestConfig_InvalidUPFAddress
- TestConfig_MissingPcapFile
- TestConfig_InvalidCIDR
- TestConfig_ZeroSEIDStart
- TestConfig_UnknownSEIDStrategy
- TestConfig_ZeroTimeout
```

#### IE Modifier Tests (`internal/pfcp/modifier_test.go`)
```
- TestModifier_ReplaceFSEID
- TestModifier_ReplaceUEIP_IPv4
- TestModifier_ReplaceUEIP_IPv6
- TestModifier_UpdateHeaderSEID
- TestModifier_UpdateSequenceNumber
- TestModifier_PreservePDRID
- TestModifier_PreserveFARID
- TestModifier_PreserveFTEID
- TestModifier_PreserveAllOtherIEs
- TestModifier_SessionEstablishment_FullModification
- TestModifier_SessionModification_HeaderSEIDOnly
```

#### Transaction Tracker Tests (`internal/network/transaction_test.go`)
```
- TestTransactionTracker_Track_ReturnsChannel
- TestTransactionTracker_Resolve_MatchesSeqNum
- TestTransactionTracker_Timeout_Retransmits
- TestTransactionTracker_Timeout_MaxRetries_Fails
- TestTransactionTracker_ConcurrentTrackResolve
```

### 10.2 Integration Tests

#### Mock UPF (`test/integration/mock_upf_test.go`)

A mock UPF that:
- Listens on UDP port 8805
- Parses incoming PFCP messages
- Generates appropriate responses:
  - Association Setup Response with Cause=RequestAccepted
  - Session Establishment Response with random UP F-SEID
  - Session Modification Response with Cause=RequestAccepted
  - Session Deletion Response with Cause=RequestAccepted
  - Heartbeat Response

#### Integration Test Scenarios

```
- TestIntegration_AssociationSetup
  → Send Association Setup, verify response handling

- TestIntegration_SingleSession_Lifecycle
  → Establish → Modify → Delete a single session
  → Verify SEID mapping, UE IP allocation/release

- TestIntegration_MultipleSessions
  → Establish 10 sessions from pcap
  → Verify unique SEIDs and UE IPs per session

- TestIntegration_ResponseTimeout
  → Mock UPF does not respond
  → Verify retransmission and eventual timeout

- TestIntegration_SessionEstablishment_Rejected
  → Mock UPF responds with Cause=RuleCreationModificationFailure
  → Verify error handling and skip

- TestIntegration_EndToEnd_PcapReplay
  → Parse sample pcap
  → Replay all messages to mock UPF
  → Verify statistics match expected counts
```

### 10.3 Test Data

- `test/testdata/sample.pcap` - A pcap file containing:
  - 1 Association Setup Request/Response
  - Multiple Session Establishment Request/Response pairs
  - Session Modification Request/Response pairs
  - Session Deletion Request/Response pairs
  - Heartbeat Request/Response pairs

- Test with varying session counts: 1, 10, 100
- Test with both IPv4-only and dual-stack sessions

### 10.4 Test Commands

```bash
# Run all unit tests
make test

# Run unit tests with verbose output
make test-verbose

# Run integration tests (requires no port 8805 conflict)
make test-integration

# Run all tests with coverage
make test-coverage

# Run specific package tests
go test ./internal/session/... -v
go test ./internal/pfcp/... -v
```

---

## 11. Build and Development

### 11.1 Makefile Targets

```makefile
.PHONY: build test test-verbose test-integration test-coverage lint clean

BINARY=pfcp-generator
VERSION=1.0.0

build:
	go build -o $(BINARY) ./cmd/pfcp-generator/

test:
	go test ./internal/... ./pkg/...

test-verbose:
	go test -v ./internal/... ./pkg/...

test-integration:
	go test -v -tags=integration ./test/integration/...

test-coverage:
	go test -coverprofile=coverage.out ./internal/... ./pkg/...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY) coverage.out coverage.html

run: build
	./$(BINARY) --config config.yaml
```

### 11.2 Go Module Initialization

```bash
go mod init pfcp-generator
go get github.com/wmnsk/go-pfcp@v0.0.24
go get github.com/google/gopacket@v1.1.19
go get github.com/spf13/cobra@v1.8.0
go get github.com/spf13/viper@v1.18.2
go get github.com/sirupsen/logrus@v1.9.3
go get github.com/stretchr/testify@v1.8.4
```

---

## 12. Logging Guidelines

### 12.1 Log Levels

| Level | Usage |
|-------|-------|
| `debug` | Detailed message content, IE values, raw bytes |
| `info` | Message sent/received, session created/deleted, startup/shutdown |
| `warn` | Retransmission triggered, unexpected IE, decode error for single message |
| `error` | Session failure, timeout after retries, IP pool exhaustion |

### 12.2 Structured Fields

All log entries should include relevant context:

```go
log.WithFields(log.Fields{
    "msg_type":   "SessionEstablishmentRequest",
    "seq_num":    seqNum,
    "local_seid": localSEID,
    "ue_ip":      ueIP.String(),
}).Info("Sending session establishment request")
```

---

## 13. Known Considerations

### 13.1 Session Mapping Complexity

The most complex part of the implementation is mapping original pcap sessions to new sessions. The pcap may contain interleaved messages from multiple sessions. The implementation must:

1. Track which original session each message belongs to (via SEID in pcap)
2. Map original SEIDs to new SEIDs
3. Handle the case where pcap Modification/Deletion messages reference the original UPF's SEID (which differs from our UPF's SEID)

**Recommended approach:** Build the mapping during pcap parsing phase before replay:
- First pass: scan all messages, group by session (identify Establish→Modify→Delete chains)
- Second pass: replay with proper mapping

Alternatively, build mapping incrementally during replay if sessions don't interleave.

### 13.2 go-pfcp Library IE Modification

The `wmnsk/go-pfcp` library constructs messages from IEs. Modifying nested IEs (like UE IP Address inside PDI inside Create PDR) requires reconstructing the grouped IE hierarchy. The modifier must:

1. Extract child IEs from the grouped IE
2. Find and replace the target IE
3. Rebuild the grouped IE with updated children

This is the most implementation-intensive part of the modifier component.

### 13.3 PCAP Direction Detection

To determine which messages are requests (SMF→UPF) vs responses (UPF→SMF):
- **Primary method:** Check if destination port is 8805 (request) or source port is 8805 (response)
- **Fallback:** Check PFCP message type (odd = request, even = response for session messages)
- Only replay request messages; skip responses found in the pcap
