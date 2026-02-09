# PFCP Message Generator Tool - Implementation Prompt

## Project Overview
Implement a Go-based tool that acts as an SMF node in 5GC, generating PFCP messages to UPF based on a pcap file. The tool reads PFCP messages from a pcap capture, modifies session-specific identifiers, and replays them to a target UPF.

## Phase 1: Generate Design Documents

Please generate the following design documents in a `docs/` directory:

### 1. Requirements Document (`docs/requirements.md`)
Create a detailed requirements document covering:

**Functional Requirements:**
- PCAP file parsing (UDP port 8805, PFCP protocol)
- PFCP message decoding using go-pfcp library (https://github.com/wmnsk/go-pfcp)
- Session identifier management (SEID, UE IP)
- Message modification and re-encoding
- UDP transmission to target UPF
- Response handling and transaction tracking
- Support for key message types:
  - PFCP Association Setup Request/Response
  - PFCP Session Establishment Request/Response
  - PFCP Session Modification Request/Response
  - PFCP Session Deletion Request/Response
  - PFCP Heartbeat Request/Response

**Non-Functional Requirements:**
- Performance: configurable message rate, support 100+ concurrent sessions
- Reliability: handle retransmissions, response timeouts
- Observability: detailed logging, statistics tracking
- Usability: CLI interface, configuration file support
- Code quality: unit tests, clean architecture

**Out of Scope (DO NOT manage these):**
- PDR ID: already unique in pcap, use as-is
- FAR ID: already unique in pcap, use as-is
- QER ID: already unique in pcap, use as-is
- URR ID: already unique in pcap, use as-is
- F-TEID: allocated by UPF, do not modify
- Any other rule IDs within PFCP session

### 2. Architecture Document (`docs/architecture.md`)
Design the system architecture with:

**Component Design:**
```
┌─────────────────────────────────────────────────────────────┐
│                     PFCP Generator Tool                      │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface (cobra/flags)                                │
├─────────────────────────────────────────────────────────────┤
│  Config Manager  │  Statistics Collector                    │
├──────────────────┴──────────────────────────────────────────┤
│  PCAP Parser (gopacket) → PFCP Decoder (wmnsk/go-pfcp)     │
├─────────────────────────────────────────────────────────────┤
│  Session Manager                                             │
│  - SEID Allocator (sequential/random strategy)              │
│  - UE IP Pool (IPv4/IPv6)                                   │
│  - Sequence Number Tracker                                   │
├─────────────────────────────────────────────────────────────┤
│  PFCP Message Modifier                                       │
│  - Replace F-SEID (SEID + IP)                               │
│  - Replace UE IP Address                                     │
│  - Update Sequence Number                                    │
│  - Preserve PDR/FAR/QER/URR IDs                             │
├─────────────────────────────────────────────────────────────┤
│  Network Layer                                               │
│  - UDP Sender (to UPF port 8805)                            │
│  - Response Receiver                                         │
│  - Transaction Tracker (seq num matching)                   │
└─────────────────────────────────────────────────────────────┘
```

**Directory Structure:**
```
pfcp-generator/
├── cmd/
│   └── pfcp-generator/
│       └── main.go                    # CLI entry point
├── internal/
│   ├── config/
│   │   ├── config.go                  # Configuration struct and loader
│   │   └── validator.go               # Config validation
│   ├── pcap/
│   │   ├── parser.go                  # PCAP file reader
│   │   └── filter.go                  # PFCP packet filter
│   ├── pfcp/
│   │   ├── decoder.go                 # wmnsk/go-pfcp wrapper for decode
│   │   ├── encoder.go                 # wmnsk/go-pfcp wrapper for encode
│   │   ├── modifier.go                # IE modification logic
│   │   └── message_types.go           # Message type constants
│   ├── session/
│   │   ├── manager.go                 # Session lifecycle management
│   │   ├── seid_allocator.go          # SEID allocation strategies
│   │   └── ip_pool.go                 # UE IP address pool
│   ├── network/
│   │   ├── sender.go                  # UDP client to UPF
│   │   ├── receiver.go                # Response handler
│   │   └── transaction.go             # Transaction tracking
│   └── stats/
│       ├── collector.go               # Statistics aggregation
│       └── reporter.go                # Stats output/export
├── pkg/
│   └── types/
│       └── session.go                 # Shared session types
├── test/
│   ├── testdata/
│   │   └── sample.pcap                # Test PCAP files
│   └── integration/
│       └── mock_upf_test.go           # Mock UPF for testing
├── docs/
│   ├── requirements.md                # This document
│   ├── architecture.md                # Architecture design
│   └── implementation.md              # Implementation guide
├── config.yaml                        # Example configuration
├── go.mod
├── go.sum
├── Makefile                           # Build automation
└── README.md                          # Usage guide
```

**Key Design Decisions:**
- Use `wmnsk/go-pfcp` library for PFCP protocol handling
- Use `google/gopacket` for PCAP parsing
- Clean architecture with separated concerns
- Interface-based design for testability
- Configuration via YAML with CLI override flags

### 3. Implementation Guide (`docs/implementation.md`)
Provide detailed implementation specifications:

**3.1 SEID Management Strategy:**
- Local SEID (CP-assigned): Use sequential allocation starting from configurable base (default: 1)
- Remote SEID (UP-assigned): Extract from UPF responses, store in session map
- Thread-safe allocation with mutex
- SEID reuse prevention

**3.2 UE IP Pool Implementation:**
- Support IPv4 CIDR notation (e.g., 10.0.0.0/24)
- Support IPv6 prefix (e.g., 2001:db8::/48)
- Round-robin or sequential allocation
- Track allocated IPs per session
- Release on session deletion

**3.3 IE Modification Rules:**

**Must Modify:**
1. **F-SEID IE (Type 57)** - in Session Establishment Request
   - Replace SEID field with newly allocated local SEID
   - Optionally replace IPv4/IPv6 with configured SMF address

2. **UE IP Address IE (Type 93)** - in PDI of Create PDR
   - Replace with IP from UE pool
   - Maintain IPv4/IPv6 version from original
   - Update V4/V6 flags accordingly

3. **SEID in PFCP Header** - for all session-related messages
   - Use remote SEID (from UPF response) for subsequent requests
   - Use 0 for initial Session Establishment Request

4. **Sequence Number in PFCP Header**
   - Increment for each message sent
   - Maintain per-connection sequence counter

**Must Preserve (DO NOT MODIFY):**
- PDR ID (already unique)
- FAR ID (already unique)
- QER ID (already unique)
- URR ID (already unique)
- BAR ID (already unique)
- F-TEID (UPF allocates these)
- All other IEs not explicitly listed above

**3.4 Message Processing Flow:**
```
1. Read PCAP file
2. For each UDP packet on port 8805:
   a. Extract PFCP message
   b. Decode using wmnsk/go-pfcp
   c. Identify message type
   d. If Association Setup Request:
      - Update sequence number
      - Send to UPF
      - Wait for response
   e. If Session Establishment Request:
      - Allocate new SEID
      - Replace F-SEID IE
      - Allocate UE IP from pool
      - Replace UE IP Address IE
      - Update sequence number
      - Send to UPF
      - Wait for response
      - Extract remote SEID from response
      - Store session mapping (local SEID ↔ remote SEID ↔ UE IP)
   f. If Session Modification/Deletion Request:
      - Lookup remote SEID from session map
      - Update PFCP header SEID
      - Update sequence number
      - Send to UPF
      - Wait for response
   g. Handle response:
      - Match by sequence number
      - Validate message type (response vs request)
      - Update session state if needed
      - Log result
```

**3.5 Configuration Schema (YAML):**
```yaml
# Source SMF configuration
smf:
  address: "192.168.1.10"      # Local SMF IP
  port: 8805                    # PFCP port (default 8805)

# Target UPF configuration
upf:
  address: "192.168.1.20"      # UPF IP address
  port: 8805                    # UPF PFCP port

# Session configuration
session:
  seid_start: 1                 # Starting SEID value
  seid_strategy: "sequential"   # sequential | random
  ue_ip_pool: "10.60.0.0/24"   # UE IPv4 pool
  ue_ipv6_pool: "2001:db8::/48" # UE IPv6 pool (optional)

# Timing configuration
timing:
  message_interval_ms: 100      # Delay between messages (0 = as fast as possible)
  response_timeout_ms: 5000     # Wait time for UPF response
  max_retries: 3                # Retransmission attempts

# Input/Output
input:
  pcap_file: "capture.pcap"    # Input PCAP file path
  
# Logging
logging:
  level: "info"                 # debug | info | warn | error
  file: "pfcp-generator.log"   # Log file path (optional)
  console: true                 # Log to console

# Statistics
stats:
  enabled: true
  report_interval_sec: 10      # Statistics report interval
  export_file: "stats.json"    # Export stats to file (optional)
```

**3.6 Error Handling:**
- Validate PCAP file exists and is readable
- Handle malformed PFCP messages gracefully
- Detect UPF connection failures
- Report session establishment failures
- Timeout handling for responses
- Graceful shutdown on SIGINT/SIGTERM

**3.7 Testing Strategy:**

**Unit Tests:**
- SEID allocator (sequential and random)
- UE IP pool allocation/release
- IE modification functions
- Configuration validation

**Integration Tests:**
- Mock UPF that responds to PFCP messages
- End-to-end message flow
- Session lifecycle (establish → modify → delete)
- Response timeout and retry logic

**Test Data:**
- Include sample PCAP with various PFCP message types
- Test with different session counts (1, 10, 100)
- Test with IPv4 and IPv6 sessions

## Phase 2: Document Review and Refinement

After generating the documents:
1. I will review all three documents
2. I will provide feedback and modifications if needed
3. You will update the documents based on my feedback
4. We iterate until both parties agree on the final design

## Phase 3: Implementation

Once documents are approved:
1. Implement core modules in this order:
   - Configuration module (internal/config)
   - UE IP pool (internal/session/ip_pool.go)
   - SEID allocator (internal/session/seid_allocator.go)
   - PFCP decoder/encoder wrappers (internal/pfcp)
   - IE modifier (internal/pfcp/modifier.go)
   - PCAP parser (internal/pcap)
   - Network layer (internal/network)
   - Session manager (internal/session)
   - Statistics collector (internal/stats)
   - CLI interface (cmd/pfcp-generator)

2. Write unit tests for each module as implemented

3. Create example configuration file

4. Write README with usage instructions

## Phase 4: Testing with Real PCAP

Find or provide a PFCP pcap file for testing:
1. Test PCAP parsing and message extraction
2. Test session establishment with mock UPF
3. Test full message replay scenario
4. Validate statistics collection
5. Performance testing (message rate, session count)

## Implementation Notes

**Go Dependencies:**
```go
require (
    github.com/wmnsk/go-pfcp v0.0.24         // PFCP protocol
    github.com/google/gopacket v1.1.19       // PCAP parsing
    github.com/spf13/cobra v1.8.0             // CLI framework
    github.com/spf13/viper v1.18.2            // Configuration
    gopkg.in/yaml.v3 v3.0.1                   // YAML parsing
    github.com/sirupsen/logrus v1.9.3         // Logging
    github.com/stretchr/testify v1.8.4        // Testing
)
```

**Coding Standards:**
- Follow Go best practices and idioms
- Use meaningful variable/function names
- Add comments for complex logic
- Keep functions focused and small (<50 lines)
- Use interfaces for dependencies (testability)
- Handle errors explicitly (no silent failures)
- Use context.Context for cancellation

**Development Workflow:**
1. Generate documents first (this phase)
2. Review and approve documents
3. Implement one module at a time
4. Write tests for each module
5. Integrate modules incrementally
6. Test with real PCAP data
7. Document any issues or deviations

## Success Criteria

The implementation is complete when:
- [ ] All three design documents are generated and approved
- [ ] All modules are implemented with unit tests
- [ ] Integration test with mock UPF passes
- [ ] Tool can parse sample PCAP file
- [ ] Tool can modify SEID and UE IP correctly
- [ ] Tool can send messages to UPF and receive responses
- [ ] Statistics are collected and reported
- [ ] README and usage documentation complete
- [ ] Real PCAP test scenario executed successfully

## Questions to Address in Documents

1. How should we handle PFCP message retransmission if no response received?
2. Should we support multiple concurrent PCAP replays?
3. How to handle Association Setup - should we establish one association per tool run?
4. Should session deletion be automatic at end of replay or manual?
5. What statistics are most important to track?
6. Should we support filtering specific message types from PCAP?
7. IPv6 support - required or optional?
8. Should we validate PFCP messages against 3GPP spec or trust pcap content?

## Getting Started

Please begin by generating the three design documents in the `docs/` directory:
1. `docs/requirements.md`
2. `docs/architecture.md`
3. `docs/implementation.md`

After I review and approve the documents, we will proceed with implementation.
