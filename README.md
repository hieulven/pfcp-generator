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

### 1. Replay Mode (default)

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
| `--no-association` | `false` | Skip PFCP Association Setup |
| `--strip-ipv6` | `true` | Strip IPv6 from UE IP Address IEs |
| `--cleanup` | `false` | Delete all active sessions on exit |
| `--dry-run` | `false` | Parse only, no network traffic |
| `--stats-only` | `false` | Print pcap message counts and exit |

### Config File

See `config.yaml` for a fully commented example. Key sections:

```yaml
smf:
  address: "192.168.1.10"
  port: 8805

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
  cleanup_on_exit: false

timing:
  message_interval_ms: 100
  response_timeout_ms: 5000
  max_retries: 3

input:
  pcap_file: "capture.pcap"

logging:
  level: "info"
  file: ""

stats:
  enabled: true
  report_interval_sec: 10
  export_file: ""
```

## Feature Details

### SEID Allocation

Two strategies are available:

- **sequential** (default) -- SEIDs are allocated starting from `seid_start` and incrementing. Released SEIDs are reused.
- **random** -- random `uint64` values, with collision avoidance.

### UE IP Pool

A CIDR block (e.g. `10.60.0.0/16`) from which UE IPv4 addresses are allocated sequentially. Addresses wrap around and are reused when sessions are deleted. The pool size limits the maximum number of concurrent sessions.

### IPv6 Stripping

Enabled by default. When a pcap contains UE IP Address IEs with both IPv4 and IPv6, the IPv6 component is removed and only IPv4 is sent to the UPF.

### Association Setup

Enabled by default. Sends a PFCP Association Setup Request before any session messages. Disable with `--no-association` if the UPF does not require association or if it was already established.

### Session Cleanup

When `--cleanup` is set, all sessions that are still active after replay completes are deleted by sending Session Deletion Requests. This is useful when the pcap does not contain deletions for all sessions.

### Retransmission

If a response is not received within the timeout period, the request is retransmitted up to `max_retries` times using the same sequence number.

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
  network/             UDP client, receiver, transaction tracker
  pcap/                Pcap parsing with SEID mapping extraction
  pfcp/                PFCP encode/decode/modify
  session/             Session manager, SEID allocator, UE IP pool
  stats/               Statistics collection and reporting
pkg/types/             Shared data types
test/
  mockupf/             Standalone mock UPF server
  testdata/            Sample pcap and generation script
```
