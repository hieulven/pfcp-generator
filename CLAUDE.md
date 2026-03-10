# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
make build          # Build pfcp-generator binary
make test           # Run unit tests (internal/ and pkg/)
make test-verbose   # Run tests with verbose output
make test-coverage  # Generate HTML coverage report (coverage.html)
make lint           # Run golangci-lint
make mockupf        # Build mock UPF test server binary
make docker         # Build Docker image
make run            # Build and run with config.yaml
```

**System requirement**: libpcap must be installed (`dnf install libpcap-devel gcc` on RHEL, `apt-get install libpcap-dev` on Ubuntu).

To run a single test:
```bash
go test ./internal/session/... -run TestSEIDAllocator
```

End-to-end test using mock UPF:
```bash
go run ./test/mockupf/ &              # Start mock UPF on :8805
./pfcp-generator --pcap test/testdata/sample.pcap
```

## Architecture Overview

The tool acts as an **SMF (Session Management Function)** that replays PFCP traffic from pcap files toward a live UPF. It:
1. Reads PFCP messages from a pcap file (`internal/pcap/`)
2. Modifies session-specific identifiers (SEID, UE IP, sequence numbers) for each new session (`internal/pfcp/modifier.go`)
3. Sends them via UDP port 8805 and waits for UPF responses (`internal/network/`)
4. Tracks session state and correlates responses (`internal/session/manager.go`)

**Operating modes**: normal replay, `--dry-run` (parse only), `--stats-only` (count messages), `--stress` (high-performance stress test).

## Package Layout

- **`cmd/pfcp-generator/`** — Cobra/Viper CLI entry point; orchestrates startup, config loading, signal handling
- **`internal/config/`** — Config structs loaded from `config.yaml`, with CLI flag overrides; validated in `validator.go`
- **`internal/pcap/`** — Parses pcap/pcapng files via `google/gopacket`, filters UDP port 8805, returns PFCP requests
- **`internal/pfcp/`** — Decodes/encodes PFCP messages using `wmnsk/go-pfcp`; `modifier.go` replaces F-SEID, UE IP, sequence numbers while preserving PDR/FAR/QER/URR/BAR IDs; strips vendor-specific IEs (type >= 32768) when configured
- **`internal/session/`** — `manager.go` drives session lifecycle (Replay + ReplayStress modes); `grouper.go` groups pcap messages into session templates; `ratelimiter.go` provides batch-ticker rate limiting; `seid_allocator.go` uses atomic counter + free-list; `ip_pool.go` uses free-list stack for O(1) UE IP allocation
- **`internal/network/`** — Multi-source-port UDP client pool (`pool.go`), lock-free UDP client (`sender.go`), multi-conn async receiver with `sync.Pool` buffers (`receiver.go`), 64-shard transaction tracker with port-aware retransmission (`transaction.go`)
- **`internal/stats/`** — Metrics collection, console/JSON reporting, and live TUI dashboard for stress mode
- **`pkg/types/`** — Shared types: `RawPFCPMessage`, `SessionInfo`, `TransactionResult`
- **`test/mockupf/`** — Standalone mock UPF that generates valid PFCP responses; used for integration testing

## Key Design Decisions

- **Dual mode processing**: Replay mode processes messages sequentially in pcap order. Stress mode uses a worker pool with session templates, rate limiter, and session semaphore for high-throughput parallel dispatch.
- **Session correlation**: The `Manager` maintains three maps — original pcap SEID → session, local allocated SEID → session, remote UPF SEID → session — because response packets reference the remote SEID assigned by the UPF.
- **Message modification contract**: `modifier.go` replaces identifiers (SEID, UE IP, seq num), strips IPv6 and vendor-specific IEs. It does not rewrite PDR/FAR structure or other standard IEs.
- **Multi-source-port**: `UDPClientPool` manages N UDP clients on sequential ports. Round-robin dispatch via atomic counter. Retransmissions use the same port as the original request (`PortIndex` stored in `PendingTransaction`).
- **Concurrency model**: Lock-free UDP writes (UDPConn is goroutine-safe), 64-shard transaction tracker, `sync/atomic` stats counters, fixed-bucket histogram for response times (constant memory). Shutdown uses `context.Context`.
- **`internal/` packages**: Implementation is intentionally unexported; only `pkg/types` is public.
