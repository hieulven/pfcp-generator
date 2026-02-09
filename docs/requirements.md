# PFCP Message Generator - Requirements Document

## 1. Introduction

### 1.1 Purpose
This document defines the requirements for a Go-based PFCP Message Generator tool that acts as an SMF (Session Management Function) node in a 5G Core network. The tool reads PFCP messages from a pcap capture file, modifies session-specific identifiers, and replays them to a target UPF (User Plane Function).

### 1.2 Scope
The tool is intended for testing, benchmarking, and validating UPF implementations by generating realistic PFCP traffic based on captured network data.

### 1.3 Definitions
| Term | Definition |
|------|-----------|
| PFCP | Packet Forwarding Control Protocol (3GPP TS 29.244) |
| SMF | Session Management Function (control plane) |
| UPF | User Plane Function (user plane) |
| SEID | Session Endpoint Identifier |
| F-SEID | Fully Qualified SEID (SEID + IP address) |
| PDR | Packet Detection Rule |
| FAR | Forwarding Action Rule |
| QER | QoS Enforcement Rule |
| URR | Usage Reporting Rule |
| BAR | Buffering Action Rule |
| F-TEID | Fully Qualified Tunnel Endpoint Identifier |
| IE | Information Element |
| N4 | Interface between SMF and UPF |

---

## 2. Functional Requirements

### 2.1 PCAP File Parsing
| ID | Requirement | Priority |
|----|------------|----------|
| FR-01 | The tool SHALL read pcap files containing PFCP traffic | Must |
| FR-02 | The tool SHALL filter packets on UDP port 8805 | Must |
| FR-03 | The tool SHALL extract PFCP message payloads from UDP packets | Must |
| FR-04 | The tool SHALL only process request messages from the pcap (SMF→UPF direction), skipping response messages | Must |
| FR-05 | The tool SHALL report the total number of PFCP messages found in the pcap | Must |
| FR-06 | The tool SHALL support both pcap and pcapng file formats | Must |
| FR-07 | The tool SHALL support both pcap files captured on network by wireshark or tcpdump, and support pcap file that is Linux cooked | Must |

### 2.2 PFCP Message Decoding
| ID | Requirement | Priority |
|----|------------|----------|
| FR-10 | The tool SHALL decode PFCP messages using the `wmnsk/go-pfcp` library | Must |
| FR-11 | The tool SHALL identify message types from the PFCP header | Must |
| FR-12 | The tool SHALL handle malformed or unrecognized messages gracefully (log and skip) | Must |
| FR-13 | The tool SHALL distinguish between node-related (S=0) and session-related (S=1) messages | Must |

### 2.3 Supported Message Types
| ID | Requirement | Priority |
|----|------------|----------|
| FR-20 | The tool SHALL support PFCP Association Setup Request/Response | Should |
| FR-21 | The tool SHALL support PFCP Session Establishment Request/Response | Must |
| FR-22 | The tool SHALL support PFCP Session Modification Request/Response | Must |
| FR-23 | The tool SHALL support PFCP Session Deletion Request/Response | Must |
| FR-24 | The tool SHALL support PFCP Heartbeat Request/Response | Must |
| FR-25 | The tool SHALL support PFCP Association Update Request/Response | Could |
| FR-26 | The tool SHALL support PFCP Association Release Request/Response | Could |
| FR-27 | The tool SHALL support PFCP Session Report Request/Response | Should |

### 2.4 Session Identifier Management
| ID | Requirement | Priority |
|----|------------|----------|
| FR-30 | The tool SHALL allocate new local SEIDs (CP-side) for each session | Must |
| FR-31 | The tool SHALL support sequential SEID allocation starting from a configurable base value | Must |
| FR-32 | The tool SHALL support random SEID allocation as an alternative strategy | Should |
| FR-33 | The tool SHALL prevent SEID reuse across active sessions | Must |
| FR-34 | The tool SHALL extract remote SEIDs (UP-side) from UPF responses and store them | Must |
| FR-35 | The tool SHALL use the remote SEID in the PFCP header for subsequent session messages (Modification, Deletion) | Must |
| FR-36 | The tool SHALL use SEID=0 in the PFCP header for Session Establishment Requests | Must |

### 2.5 UE IP Address Management
| ID | Requirement | Priority |
|----|------------|----------|
| FR-40 | The tool SHALL allocate UE IP addresses from a configurable IPv4 CIDR pool | Must |
| FR-41 | The tool SHALL clear UE IPv6 if it exits on pcap file, change UE IP flag to use only IPv4. This feature is control by a flag on config file | Must |
| FR-42 | The tool SHALL assign a unique UE IP to each session | Must |
| FR-43 | The tool SHALL release UE IPs when sessions are deleted | Must |
| FR-44 | The tool SHALL report an error when the IP pool is exhausted | Must |

### 2.6 Message Modification and Re-encoding
| ID | Requirement | Priority |
|----|------------|----------|
| FR-50 | The tool SHALL replace the F-SEID IE with the newly allocated local SEID and configured SMF IP | Must |
| FR-51 | The tool SHALL replace UE IP Address IEs in PDI with the allocated UE IP | Must |
| FR-52 | The tool SHALL update the SEID in the PFCP header for session-related messages | Must |
| FR-53 | The tool SHALL update the sequence number in the PFCP header | Must |
| FR-54 | The tool SHALL preserve all PDR IDs as-is from the pcap | Must |
| FR-55 | The tool SHALL preserve all FAR IDs as-is from the pcap | Must |
| FR-56 | The tool SHALL preserve all QER IDs as-is from the pcap | Must |
| FR-57 | The tool SHALL preserve all URR IDs as-is from the pcap | Must |
| FR-58 | The tool SHALL preserve all BAR IDs as-is from the pcap | Must |
| FR-59 | The tool SHALL NOT modify F-TEID IEs (UPF allocates these) | Must |
| FR-60 | The tool SHALL preserve all other IEs not explicitly listed for modification | Must |
| FR-61 | The tool SHALL re-encode modified messages using `wmnsk/go-pfcp` | Must |

### 2.7 Network Transmission
| ID | Requirement | Priority |
|----|------------|----------|
| FR-70 | The tool SHALL send PFCP messages via UDP to the target UPF | Must |
| FR-71 | The tool SHALL send to configurable UPF IP and port (default 8805) | Must |
| FR-72 | The tool SHALL bind to a configurable local SMF IP and port | Must |
| FR-73 | The tool SHALL support a configurable inter-message delay | Must |
| FR-74 | The tool SHALL support a dry-run mode (parse and modify only, no network send) | Should |

### 2.8 Response Handling
| ID | Requirement | Priority |
|----|------------|----------|
| FR-80 | The tool SHALL receive and parse PFCP responses from the UPF | Must |
| FR-81 | The tool SHALL match responses to requests using sequence numbers | Must |
| FR-82 | The tool SHALL extract the remote SEID from Session Establishment Responses | Must |
| FR-83 | The tool SHALL validate the Cause IE in responses | Must |
| FR-84 | The tool SHALL log response outcomes (accepted, rejected, error) | Must |
| FR-85 | The tool SHALL respond to Heartbeat Requests from the UPF | Should |

### 2.9 Transaction Tracking
| ID | Requirement | Priority |
|----|------------|----------|
| FR-90 | The tool SHALL track pending transactions (request sent, awaiting response) | Must |
| FR-91 | The tool SHALL implement configurable response timeouts | Must |
| FR-92 | The tool SHALL support configurable retransmission attempts on timeout | Must |
| FR-93 | The tool SHALL report timed-out transactions | Must |

### 2.10 Association Management
| ID | Requirement | Priority |
|----|------------|----------|
| FR-100 | The tool SHALL establish one PFCP Association per tool run | Must |
| FR-101 | The tool SHALL send Association Setup Request before any session messages | Must |
| FR-102 | The tool SHALL abort if Association Setup fails | Must |
| FR-103 | The tool have control flag on configuration to enable/disable this feature | Must |

### 2.11 Session Lifecycle
| ID | Requirement | Priority |
|----|------------|----------|
| FR-110 | The tool SHALL replay sessions in the order they appear in the pcap | Must |
| FR-111 | The tool SHALL map original pcap sessions to new sessions with fresh identifiers | Must |
| FR-112 | The tool SHALL support an option to automatically delete all sessions at the end of replay | Should |
| FR-113 | The tool SHALL delete sessions if there is PFCP session deletion request at the end of the replay | Should |

---

## 3. Non-Functional Requirements

### 3.1 Performance
| ID | Requirement | Priority |
|----|------------|----------|
| NFR-01 | The tool SHALL support configurable message rate (messages per second) | Must |
| NFR-02 | The tool SHALL support upto 50k concurrent sessions | Must |
| NFR-03 | The tool SHALL use efficient memory management for large pcap files | Should |

### 3.2 Reliability
| ID | Requirement | Priority |
|----|------------|----------|
| NFR-10 | The tool SHALL handle retransmissions with configurable retry count and timeout | Must |
| NFR-11 | The tool SHALL handle UPF connection failures gracefully | Must |
| NFR-12 | The tool SHALL perform graceful shutdown on SIGINT/SIGTERM | Must |
| NFR-13 | The tool SHALL clean up sessions on shutdown when possible | Should |

### 3.3 Observability
| ID | Requirement | Priority |
|----|------------|----------|
| NFR-20 | The tool SHALL provide structured logging with configurable levels (debug, info, warn, error) | Must |
| NFR-21 | The tool SHALL log to both console and file | Must |
| NFR-22 | The tool SHALL collect and report statistics (messages sent/received, errors, sessions, duration, rate) | Must |
| NFR-23 | The tool SHALL support periodic statistics reporting at configurable intervals | Should |
| NFR-24 | The tool SHALL support exporting statistics to a JSON file | Should |

### 3.4 Usability
| ID | Requirement | Priority |
|----|------------|----------|
| NFR-30 | The tool SHALL provide a CLI interface with clear help text | Must |
| NFR-31 | The tool SHALL support YAML configuration files | Must |
| NFR-32 | The tool SHALL allow CLI flags to override configuration file values | Must |
| NFR-33 | The tool SHALL validate configuration before execution | Must |
| NFR-34 | The tool SHALL display a summary of configuration at startup | Should |

### 3.5 Code Quality
| ID | Requirement | Priority |
|----|------------|----------|
| NFR-40 | The tool SHALL follow Go best practices and idioms | Must |
| NFR-41 | The tool SHALL have unit tests for core logic modules | Must |
| NFR-42 | The tool SHALL use interfaces for dependency injection and testability | Must |
| NFR-43 | The tool SHALL use `context.Context` for cancellation and timeouts | Must |
| NFR-44 | The tool SHALL provide a Makefile for build automation | Should |

---

## 4. Out of Scope

The following items are explicitly **out of scope** and SHALL NOT be managed by the tool:

| Item | Reason |
|------|--------|
| PDR ID management | Already unique per session in pcap; use as-is |
| FAR ID management | Already unique per session in pcap; use as-is |
| QER ID management | Already unique per session in pcap; use as-is |
| URR ID management | Already unique per session in pcap; use as-is |
| BAR ID management | Already unique per session in pcap; use as-is |
| F-TEID modification | Allocated by UPF; do not modify |
| GTP-U tunnel management | Outside PFCP control plane scope |
| Multiple concurrent pcap replays | Single pcap replay per tool run |
| PFCP message generation from scratch | Tool replays from pcap, not generating new sessions |
| N4 interface encryption (TLS/DTLS) | Not required for testing scenarios |

---

## 5. Design Questions and Decisions

| # | Question | Decision |
|---|---------|----------|
| 1 | How to handle retransmission if no response received? | Retransmit up to `max_retries` times with the same sequence number, then log failure and continue to next message |
| 2 | Support multiple concurrent pcap replays? | No. Single replay per tool run. Run multiple instances for parallel testing |
| 3 | How to handle Association Setup? | Establish one association per tool run. Must succeed before session messages are sent. Could be turn off by configuration |
| 4 | Should session deletion be automatic at end of replay? | Configurable. Default: no auto-deletion. Optional flag `--cleanup` to delete all sessions on completion |
| 5 | What statistics to track? | Messages sent/received per type, success/failure counts, session counts, response times (min/avg/max), overall duration, message rate |
| 6 | Support filtering specific message types from pcap? | Yes, as a "should-have" feature. Allow `--message-filter` flag |
| 7 | IPv6 support? | Should-have. IPv4 is must-have. IPv6 pool allocation is optional. Optionally turn off in configuration |
| 8 | Validate PFCP messages against 3GPP spec? | No. Trust pcap content. Only validate what is necessary for modification (F-SEID, UE IP presence) |

---

## 6. Assumptions and Constraints

### Assumptions
- The input pcap file contains valid PFCP messages captured from a real or simulated 5G network
- The pcap contains complete session lifecycles (establishment, modification, deletion). exit error if establishment not exit, auto delete at the end if deletion not exit on pcap (optionally turn on/off by config)
- The target UPF is reachable via UDP and compliant with 3GPP TS 29.244
- Rule IDs (PDR, FAR, QER, URR, BAR) in the pcap are already unique per session and do not need remapping

### Constraints
- The tool runs on a single host (not distributed)
- The tool uses Go 1.21 or later
- Dependencies are limited to well-maintained open-source libraries
- The tool operates as a single SMF node (one Node ID)
