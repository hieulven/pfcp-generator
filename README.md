# PFCP Generator

A Go-based PFCP message generator that replays pcap captures to a UPF. Acts as an SMF node on the N4 interface, reading PFCP messages from a pcap file, replacing session-specific identifiers (SEID, UE IP, sequence numbers), and sending them to a target UPF.

## Requirements

- Go 1.25+ (CGO enabled)
- libpcap / libpcap-devel

### RHEL / CentOS

```bash
dnf install libpcap-devel gcc
```

### Debian / Ubuntu

```bash
apt-get install libpcap-dev
```

### macOS

```bash
# libpcap is included with Xcode command-line tools
xcode-select --install
```

## Pre-built Binaries

Pre-built linux/amd64 binaries are available in the `dist/` directory, compiled on UBI 8.10 and compatible with RHEL 7.9+. The only runtime dependency is `libpcap`:

```bash
# RHEL 7.9
yum install -y libpcap

# RHEL 8.10
dnf install -y libpcap
```

Copy to the target machine and run:

```bash
scp dist/pfcp-generator user@host:/usr/local/bin/
```

## Build

```bash
make build
```

Or directly:

```bash
CGO_ENABLED=1 go build -o pfcp-generator ./cmd/pfcp-generator/
```

## Docker (RHEL 8.10)

Build the container image:

```bash
docker build -t pfcp-generator .
```

The Dockerfile uses a multi-stage build: UBI 8.10 with Go for compilation, UBI 8.10 minimal for the runtime image. Both `pfcp-generator` and the `mockupf` test server are included.

Run:

```bash
docker run --rm --network host \
  pfcp-generator \
    --pcap /data/capture.pcap \
    --smf-ip 192.168.1.10 \
    --upf-ip 192.168.1.20 \
    --ue-pool 10.60.0.0/16
```

Run the mock UPF inside the container:

```bash
docker run --rm --network host \
  --entrypoint mockupf \
  pfcp-generator --addr 0.0.0.0:8805
```

## Modes of Operation

### 1. Stress Test Mode

High-performance mode for load/stress testing a UPF. Sessions are created from pcap templates and cycled continuously with configurable TPS and concurrency.

```bash
pfcp-generator \
  --pcap capture.pcap \
  --smf-ip 192.168.1.10 \
  --upf-ip 192.168.1.20 \
  --ue-pool 10.60.0.0/8 \
  --stress --tps 50000 --active-sessions 10000 --duration 3600
```

**Target capabilities:**

| Parameter | Target |
|-----------|--------|
| Transactions/sec | 50,000 |
| Active PDU sessions | 10,000 |
| Test duration | 10+ hours continuous |
| Steady-state memory | ~100 MB |

The tool groups pcap messages into session templates (Establishment + Modifications + Deletion), then dispatches them across a worker pool. A rate limiter controls TPS, and a semaphore caps concurrent active sessions.

**Architecture highlights:**
- Multi-source-port UDP pool with round-robin dispatch (`--source-ports 16`)
- Lock-free UDP writes (Go's `UDPConn` is goroutine-safe)
- 64-shard transaction tracker to reduce lock contention
- Atomic counters + fixed-bucket histogram for stats (constant memory)
- `sync.Pool` for receive buffer reuse
- Batch-ticker rate limiter (50 tokens/ms at 50K TPS)
- Free-list based IP pool and SEID allocator (O(1) allocate/release)
- Live terminal dashboard with 1-second refresh (TPS, sessions, response times, per-message-type stats)
- Logs auto-redirect to file (`pfcp-generator.log`) to keep the terminal clean

**Live dashboard output:**

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    PFCP Generator - Stress Test Dashboard                    │
├──────────────────────────────────────────────────────────────────────────────┤
│ Elapsed: 0m10s          TPS: 2,377 current / 2,377 avg  (target: 3,000)     │
│ Total Sent: 23,780         Total Received: 23,720                           │
├──────────────────────────────────────────────────────────────────────────────┤
│ Sessions   Established: 6,207     Active: 6,195     Deleted: 12   Failed: 0 │
├──────────────────────────────────────────────────────────────────────────────┤
│ Response   Min: 23us       Avg: 157us      P99: 2.000ms    Max: 9.403ms     │
├──────────────────────┬───────────┬───────────┬───────────┬─────────┬─────────┤
│ Message Type         │      Sent │      Recv │   Success │  Failed │ Timeout │
├──────────────────────┼───────────┼───────────┼───────────┼─────────┼─────────┤
│ Establishment Req    │     6,207 │         0 │     6,207 │       0 │       0 │
│ Establishment Resp   │         0 │     6,207 │         0 │       0 │       0 │
│ Modification Req     │    17,550 │         0 │    17,501 │       0 │      49 │
│ Modification Resp    │         0 │    17,501 │         0 │       0 │       0 │
│ Deletion Req         │        23 │         0 │        12 │       0 │      11 │
│ Deletion Resp        │         0 │        12 │         0 │       0 │       0 │
└──────────────────────┴───────────┴───────────┴───────────┴─────────┴─────────┘
```

### 2. Replay Mode (default)

Parses the pcap, modifies each PFCP request with new identifiers, sends them to the target UPF, and waits for responses.

```bash
pfcp-generator \
  --pcap capture.pcap \
  --smf-ip 192.168.1.10 \
  --upf-ip 192.168.1.20 \
  --ue-pool 10.60.0.0/16
```

The tool processes messages in pcap order:

1. **Association Setup** (if enabled) -- sent first to register with the UPF.
2. **Session Establishment** -- allocates a new SEID and UE IP per session, replaces F-SEID and UE IP Address IEs.
3. **Session Modification** -- looks up the session by the original pcap SEID and sends with the live remote SEID.
4. **Session Deletion** -- same lookup, then releases the SEID and UE IP back to the pool.
5. **Heartbeat** -- forwarded with an updated sequence number.

After all messages are sent, a statistics summary is printed.

### 2. Dry-Run Mode

Parses and validates the pcap without sending any traffic. Useful for checking that a pcap file is well-formed before a live test.

```bash
pfcp-generator --pcap capture.pcap --dry-run
```

### 3. Stats-Only Mode

Prints a count of each PFCP message type found in the pcap and exits.

```bash
pfcp-generator --pcap capture.pcap --stats-only
```

Example output:

```
PCAP Message Statistics:
  AssociationSetupRequest                  1
  AssociationSetupResponse                 1
  SessionEstablishmentRequest              3
  SessionEstablishmentResponse             3
  SessionModificationRequest               1
  SessionModificationResponse              1
  SessionDeletionRequest                   1
  SessionDeletionResponse                  1
  HeartbeatRequest                         1
  HeartbeatResponse                        1
  Total:                                   14
```

## Configuration

The tool reads from a YAML config file (default `config.yaml`) and/or CLI flags. CLI flags override config file values.

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `config.yaml` | Config file path |
| `--pcap` | | Input pcap file path |
| `--smf-ip` | | Local SMF IP address to bind |
| `--upf-ip` | | Target UPF IP address |
| `--upf-port` | `8805` | Target UPF port |
| `--ue-pool` | | UE IPv4 address pool (CIDR) |
| `--seid-start` | `1` | Starting SEID value |
| `--seid-strategy` | `sequential` | SEID allocation: `sequential` or `random` |
| `--message-interval` | `100` | Delay between messages (ms), 0 = no delay |
| `--timeout` | `5000` | Response timeout (ms) |
| `--max-retries` | `3` | Max retransmission attempts per message |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--source-ports` | `1` | Number of source UDP ports (1-256) |
| `--no-association` | `false` | Skip PFCP Association Setup |
| `--strip-ipv6` | `true` | Strip IPv6 from UE IP Address IEs |
| `--strip-vendor-ies` | `true` | Strip vendor-specific IEs (type >= 32768) |
| `--repeat` | `1` | Number of replay iterations (0 = infinite) |
| `--repeat-interval` | `0` | Delay between repeat iterations (ms) |
| `--cleanup` | `false` | Delete all active sessions on exit |
| `--dry-run` | `false` | Parse only, no network traffic |
| `--stats-only` | `false` | Print pcap message counts and exit |
| `--stress` | `false` | Enable high-performance stress test mode |
| `--tps` | `50000` | Target transactions per second (stress mode) |
| `--active-sessions` | `10000` | Max concurrent active sessions (stress mode) |
| `--duration` | `0` | Test duration in seconds (stress mode, 0=unlimited) |
| `--log-file` | | Log file path (auto-set to `pfcp-generator.log` in stress mode) |

### Config File

See `config.yaml` for a fully commented example. Key sections:

```yaml
smf:
  address: "192.168.1.10"
  port: 8805
  source_ports: 1          # Number of source UDP ports (1-256)

upf:
  address: "192.168.1.20"
  port: 8805

association:
  enabled: true

session:
  seid_start: 1
  seid_strategy: "sequential"
  ue_ip_pool: "10.60.0.0/16"
  strip_ipv6: true
  strip_vendor_ies: true   # Strip vendor-specific IEs (type >= 32768)
  cleanup_on_exit: false

timing:
  message_interval_ms: 100
  response_timeout_ms: 5000
  max_retries: 3
  repeat_interval_ms: 0

input:
  pcap_file: "capture.pcap"
  repeat_count: 1

logging:
  level: "info"
  file: ""                 # Log file path (auto-set in stress mode)

stats:
  enabled: true
  report_interval_sec: 10
  export_file: ""

# Stress test mode (overrides timing/repeat settings)
stress:
  enabled: false
  tps: 50000              # Target transactions per second
  active_sessions: 10000  # Max concurrent active sessions
  duration_sec: 0         # Test duration (0 = unlimited)
```

## Feature Details

### SEID Allocation

Two strategies are available:

- **sequential** (default) -- SEIDs are allocated starting from `seid_start` and incrementing. Released SEIDs are reused.
- **random** -- random `uint64` values, with collision avoidance.

### UE IP Pool

A CIDR block (e.g. `10.60.0.0/16`) from which UE IPv4 addresses are allocated sequentially. Addresses wrap around and are reused when sessions are deleted. The pool size limits the maximum number of concurrent sessions.

### Multi-Source-Port

The `--source-ports` flag (default 1) controls how many source UDP ports are used for sending. Ports are allocated sequentially starting from the SMF port (e.g. `--source-ports 16` uses ports 8805-8820). Messages are distributed across ports using round-robin. Retransmissions always use the same port as the original request.

Multiple source ports help distribute load across CPU cores via RSS hashing and are more realistic for high-throughput testing.

### IPv6 Stripping

Enabled by default. When a pcap contains UE IP Address IEs with both IPv4 and IPv6, the IPv6 component is removed and only IPv4 is sent to the UPF.

### Vendor IE Stripping

Enabled by default (`--strip-vendor-ies`). Removes vendor-specific IEs (PFCP IE type >= 32768) from all outgoing messages. These are enterprise-specific extensions that may not be understood by the target UPF. The stripping is applied recursively to all grouped IEs (CreatePDR, CreateFAR, PDI, etc.).

### Association Setup

Enabled by default. Sends a PFCP Association Setup Request before any session messages. Disable with `--no-association` if the UPF does not require association or if it was already established.

### Session Cleanup

When `--cleanup` is set, all sessions that are still active after replay completes are deleted by sending Session Deletion Requests. This is useful when the pcap does not contain deletions for all sessions.

### Pcap Repeat

The `--repeat` flag controls how many times the pcap is replayed. Between iterations, active sessions are cleaned up and session state is reset (SEIDs and UE IPs are released back to the pool).

```bash
# Replay 5 times with 1 second between iterations
pfcp-generator --pcap capture.pcap --repeat 5 --repeat-interval 1000 ...

# Replay indefinitely until Ctrl+C
pfcp-generator --pcap capture.pcap --repeat 0 ...
```

### IPv4 Fragment Reassembly

PFCP messages that span multiple IP fragments (e.g. large Session Establishment Requests with many PDRs/FARs) are transparently reassembled before parsing. This applies to both replay and stats-only modes.

### Retransmission

If a response is not received within the timeout period, the request is retransmitted up to `max_retries` times using the same sequence number and the same source port.

### Statistics

After replay, a summary is printed showing per-message-type counts (sent, received, success, timeout) and response time percentiles. Stats can be exported to a JSON file with `stats.export_file`.

## Mock UPF Server

A standalone mock UPF is included for end-to-end testing without a real UPF.

```bash
go run ./test/mockupf/ --addr 127.0.0.1:8805
```

It responds to all standard PFCP messages:

| Request | Response |
|---------|----------|
| Association Setup | Cause=Accepted, NodeID, RecoveryTS |
| Session Establishment | Allocates UP SEID, returns F-SEID |
| Session Modification | Cause=Accepted |
| Session Deletion | Removes session, Cause=Accepted |
| Heartbeat | RecoveryTS |

### End-to-End Test

Terminal 1 -- start the mock UPF:

```bash
go run ./test/mockupf/ --addr 127.0.0.1:18805
```

Terminal 2 -- run the generator against it:

```bash
./pfcp-generator \
  --pcap test/testdata/sample.pcap \
  --smf-ip 127.0.0.1 \
  --upf-ip 127.0.0.1 --upf-port 18805 \
  --ue-pool 10.60.0.0/24 \
  --message-interval 50
```

Expected result: 7 sent, 7 received, 0 errors, 0 timeouts.

### Generating Test Data

A pcap with sample PFCP traffic can be regenerated:

```bash
go run test/testdata/generate_pcap.go
```

This creates `test/testdata/sample.pcap` containing 14 packets (association, 3 establishments, 1 modification, 1 deletion, 1 heartbeat -- each with request and response).

## Project Structure

```
cmd/pfcp-generator/    CLI entry point
internal/
  config/              Configuration loading and validation
  network/
    sender.go          Lock-free UDP client
    pool.go            Multi-source-port UDP client pool (round-robin)
    receiver.go        Multi-conn async receiver with sync.Pool buffers
    transaction.go     64-shard transaction tracker (port-aware retransmission)
  pcap/                Pcap parsing with SEID mapping extraction
  pfcp/                PFCP encode/decode/modify (vendor IE stripping)
  session/
    manager.go         Session orchestration (Replay + ReplayStress)
    grouper.go         Groups pcap messages into session templates
    ratelimiter.go     Batch-ticker rate limiter for high TPS
    ip_pool.go         Free-list based UE IP allocation
    seid_allocator.go  Atomic counter + free-list SEID allocation
  stats/
    collector.go       Atomic counters + fixed-bucket histogram
    reporter.go        Console/JSON reporting + live TUI dashboard
pkg/types/             Shared data types
test/
  mockupf/             High-performance mock UPF (sharded, multi-reader)
  testdata/            Sample pcap and generation script
```
