# PFCP Protocol Reference for Implementation

## Overview
This document provides technical reference information for implementing the PFCP message generator tool.

## PFCP Protocol Basics (3GPP TS 29.244)

### Transport
- Protocol: UDP
- Port: 8805 (both source and destination typically)
- Runs on N4 interface (SMF ↔ UPF in 5G)

### Message Structure
```
┌─────────────────────────────────────────┐
│         PFCP Header (Variable)          │
├─────────────────────────────────────────┤
│    Information Element 1 (TLV)          │
├─────────────────────────────────────────┤
│    Information Element 2 (TLV)          │
├─────────────────────────────────────────┤
│              ...                        │
└─────────────────────────────────────────┘
```

### PFCP Header Format
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┐
│Version│ Spare │M│M│S│        Message Type           │
├───────┴───────┴─┴─┴─┴───────────────────────────────┤
│                    Message Length                   │
├─────────────────────────────────────────────────────┤
│                   SEID (if S=1)                     │
│                    (8 octets)                       │
├─────────────────────────────────────────────────────┤
│                  Sequence Number                    │
│                    (3 octets)                       │
├─────────────────────────────────────────────────────┤
│    Message Priority   │  Spare                      │
└─────────────────────────────────────────────────────┘

Version: 1
S (SEID flag): 1 = SEID present, 0 = no SEID
```

**Key Points:**
- SEID is ONLY present in session-related messages (S=1)
- Node-related messages have S=0 (no SEID)
- Sequence number is 3 bytes (24-bit)
- Message length excludes first 4 mandatory bytes

### Message Types (Key ones for this tool)

**Node-related Messages (SEID not present):**
- 5: PFCP Association Setup Request
- 6: PFCP Association Setup Response
- 7: PFCP Association Update Request
- 8: PFCP Association Update Response
- 9: PFCP Association Release Request
- 10: PFCP Association Release Response
- 1: PFCP Heartbeat Request
- 2: PFCP Heartbeat Response

**Session-related Messages (SEID present):**
- 50: PFCP Session Establishment Request
- 51: PFCP Session Establishment Response
- 52: PFCP Session Modification Request
- 53: PFCP Session Modification Response
- 54: PFCP Session Deletion Request
- 55: PFCP Session Deletion Response
- 56: PFCP Session Report Request
- 57: PFCP Session Report Response

### Information Elements (IEs)

#### IE Format (TLV)
```
┌────────────────────────────────┐
│   IE Type (2 octets)           │
├────────────────────────────────┤
│   IE Length (2 octets)         │
├────────────────────────────────┤
│   IE Value (variable)          │
└────────────────────────────────┘
```

#### Critical IEs for Session Distinction

**1. F-SEID (Fully Qualified SEID) - IE Type 57**
```
┌────────────────────────────────┐
│ Flags: V4|V6|CH|CHID (1 octet) │
├────────────────────────────────┤
│ SEID (8 octets)                │
├────────────────────────────────┤
│ IPv4 Address (4 octets, if V4) │
├────────────────────────────────┤
│ IPv6 Address (16 octets, if V6)│
└────────────────────────────────┘
```
- Appears in: Session Establishment Request
- Purpose: CP provides its SEID and IP to UP
- **Must modify:** SEID field, optionally IPv4/IPv6

**2. UE IP Address - IE Type 93**
```
┌────────────────────────────────┐
│ Flags: V6|V4|S/D|IPv6D|... etc │
├────────────────────────────────┤
│ IPv4 Address (4 octets, if V4) │
├────────────────────────────────┤
│ IPv6 Address (16 octets, if V6)│
├────────────────────────────────┤
│ IPv6 Prefix Length (if IPv6D)  │
└────────────────────────────────┘
```
- Appears in: PDI (Packet Detection Information) of Create PDR
- Purpose: Identifies UE's assigned IP
- **Must modify:** IPv4/IPv6 address field
- **Preserve:** V4/V6 flags (must match address type)

**3. F-TEID (Fully Qualified TEID) - IE Type 21**
```
┌────────────────────────────────┐
│ Flags: V4|V6|CH|CHID (1 octet) │
├────────────────────────────────┤
│ TEID (4 octets)                │
├────────────────────────────────┤
│ IPv4 Address (4 octets, if V4) │
├────────────────────────────────┤
│ IPv6 Address (16 octets, if V6)│
├────────────────────────────────┤
│ Choose ID (if CH=1)            │
└────────────────────────────────┘
```
- Appears in: Multiple locations (PDI, FAR)
- Purpose: GTP-U tunnel endpoint (N3/N9 interface)
- **DO NOT MODIFY**: UPF allocates these

#### IEs to Preserve (DO NOT MODIFY)

**Rule IDs (all 2-octet values):**
- PDR ID (IE Type 56) - Already unique per session in pcap
- FAR ID (IE Type 108) - Already unique per session in pcap
- QER ID (IE Type 109) - Already unique per session in pcap
- URR ID (IE Type 81) - Already unique per session in pcap
- BAR ID (IE Type 88) - Already unique per session in pcap

**Other IEs to preserve:**
- Network Instance (IE Type 22)
- QFI (QoS Flow Identifier) (IE Type 124)
- QoS Profile (IE Type varies)
- Apply Action in FAR (IE Type 44)
- Outer Header Creation in FAR (IE Type 84)
- All measurement/reporting related IEs

## Go Library: wmnsk/go-pfcp

### Installation
```bash
go get -u github.com/wmnsk/go-pfcp
```

### Key Packages
```go
import (
    "github.com/wmnsk/go-pfcp/message"
    "github.com/wmnsk/go-pfcp/ie"
)
```

### Message Parsing Example
```go
// Parse received PFCP message
msg, err := message.Parse(buffer)
if err != nil {
    log.Fatal(err)
}

// Type assertion to specific message
switch msg.MessageType() {
case message.MsgTypeSessionEstablishmentRequest:
    req := msg.(*message.SessionEstablishmentRequest)
    // Access fields
    nodeID := req.NodeID
    createPDR := req.CreatePDR
    // ...
}
```

### Message Creation Example
```go
// Create Session Establishment Request
req := message.NewSessionEstablishmentRequest(
    sequenceNumber,
    0, // SEID (0 for initial request)
    ie.NewNodeID("", "", "smf.example.com"),
    ie.NewFSEID(seid, "192.168.1.10", ""),
    ie.NewCreatePDR(
        ie.NewPDRID(1),
        ie.NewPrecedence(100),
        ie.NewPDI(
            ie.NewSourceInterface(ie.SrcInterfaceAccess),
            ie.NewFTEID(0x01, teid, "10.0.0.1", "", 0),
            ie.NewUEIPAddress(0x02, "10.60.0.1", "", 0, 0),
        ),
        ie.NewFARID(1),
    ),
    // More IEs...
)

// Serialize to bytes
b, err := req.Marshal()
if err != nil {
    log.Fatal(err)
}

// Send via UDP
conn.WriteTo(b, udpAddr)
```

### IE Access and Modification
```go
// Get F-SEID IE from Session Establishment Request
fseidIE := req.FSEID
if fseidIE != nil {
    seid, err := fseidIE.FSEID()
    if err != nil {
        log.Fatal(err)
    }
    // seid is a *ie.FSEIDFields struct
    newSEID := uint64(12345)
    
    // Create new F-SEID IE with modified SEID
    newFSEIDIE := ie.NewFSEID(newSEID, seid.IPv4Address.String(), "")
    
    // Replace in message
    req.FSEID = newFSEIDIE
}

// Access nested IEs in Create PDR
for _, pdr := range req.CreatePDR {
    pdrID, _ := pdr.PDRID()
    
    // Get PDI (grouped IE)
    pdi := pdr.PDI
    if pdi != nil {
        // Find UE IP Address IE within PDI
        for _, childIE := range pdi.ChildIEs {
            if childIE.Type == ie.UEIPAddress {
                ueIP, _ := childIE.UEIPAddress()
                // Modify UE IP
                newUEIP := net.ParseIP("10.60.0.5")
                newUEIPIE := ie.NewUEIPAddress(0x02, newUEIP.String(), "", 0, 0)
                // Replace in PDI's child IEs
                // (need to rebuild PDI with new IE)
            }
        }
    }
}
```

### Sequence Number Management
```go
type PFCPConnection struct {
    seqNum uint32
    mu     sync.Mutex
}

func (c *PFCPConnection) NextSeqNum() uint32 {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.seqNum++
    if c.seqNum > 0xFFFFFF { // 24-bit max
        c.seqNum = 1
    }
    return c.seqNum
}
```

## PCAP Parsing with gopacket

### Installation
```bash
go get -u github.com/google/gopacket
go get -u github.com/google/gopacket/pcap
```

### Reading PFCP Messages from PCAP
```go
import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

func parsePCAP(filename string) error {
    handle, err := pcap.OpenOffline(filename)
    if err != nil {
        return err
    }
    defer handle.Close()
    
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    
    for packet := range packetSource.Packets() {
        // Check for UDP layer
        udpLayer := packet.Layer(layers.LayerTypeUDP)
        if udpLayer == nil {
            continue
        }
        
        udp, _ := udpLayer.(*layers.UDP)
        
        // Filter PFCP port (8805)
        if udp.DstPort != 8805 && udp.SrcPort != 8805 {
            continue
        }
        
        // UDP payload contains PFCP message
        pfcpData := udp.Payload
        
        // Parse PFCP message
        msg, err := message.Parse(pfcpData)
        if err != nil {
            log.Printf("Failed to parse PFCP: %v", err)
            continue
        }
        
        // Process message
        processMessage(msg)
    }
    
    return nil
}
```

## Session Management Data Structures

### Session State
```go
type SessionState struct {
    LocalSEID  uint64           // CP-assigned SEID
    RemoteSEID uint64           // UP-assigned SEID
    UEIP       net.IP           // Assigned UE IP
    CreatedAt  time.Time
    PDRs       []uint16         // PDR IDs (preserve from pcap)
    FARs       []uint32         // FAR IDs (preserve from pcap)
}

type SessionManager struct {
    sessions      map[uint64]*SessionState // key: local SEID
    seidAllocator *SEIDAllocator
    ipPool        *UEIPPool
    mu            sync.RWMutex
}
```

### SEID Allocator
```go
type SEIDAllocator struct {
    strategy  string // "sequential" or "random"
    nextSEID  uint64
    usedSEIDs map[uint64]bool
    mu        sync.Mutex
}

func (s *SEIDAllocator) Allocate() uint64 {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    switch s.strategy {
    case "sequential":
        for {
            seid := s.nextSEID
            s.nextSEID++
            if !s.usedSEIDs[seid] {
                s.usedSEIDs[seid] = true
                return seid
            }
        }
    case "random":
        for {
            seid := rand.Uint64()
            if seid == 0 || s.usedSEIDs[seid] {
                continue
            }
            s.usedSEIDs[seid] = true
            return seid
        }
    }
    return 0
}

func (s *SEIDAllocator) Release(seid uint64) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.usedSEIDs, seid)
}
```

### UE IP Pool
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
        return nil, err
    }
    
    // Start from network address + 1
    nextIP := make(net.IP, len(ipnet.IP))
    copy(nextIP, ipnet.IP)
    nextIP[len(nextIP)-1]++
    
    return &UEIPPool{
        cidr:      ipnet,
        nextIP:    nextIP,
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
            return nil, fmt.Errorf("IP pool exhausted")
        }
        
        ipStr := p.nextIP.String()
        if !p.allocated[ipStr] {
            p.allocated[ipStr] = true
            result := make(net.IP, len(p.nextIP))
            copy(result, p.nextIP)
            p.incrementIP()
            return result, nil
        }
        
        p.incrementIP()
        
        // Prevent infinite loop
        if p.nextIP.Equal(startIP) {
            return nil, fmt.Errorf("IP pool exhausted")
        }
    }
}

func (p *UEIPPool) incrementIP() {
    for i := len(p.nextIP) - 1; i >= 0; i-- {
        p.nextIP[i]++
        if p.nextIP[i] > 0 {
            break
        }
    }
}
```

## Testing Considerations

### Unit Test Examples
```go
func TestSEIDAllocator_Sequential(t *testing.T) {
    allocator := NewSEIDAllocator("sequential", 1)
    
    seid1 := allocator.Allocate()
    seid2 := allocator.Allocate()
    
    assert.Equal(t, uint64(1), seid1)
    assert.Equal(t, uint64(2), seid2)
    assert.NotEqual(t, seid1, seid2)
}

func TestUEIPPool_Allocate(t *testing.T) {
    pool, _ := NewUEIPPool("10.60.0.0/24")
    
    ip1, _ := pool.Allocate()
    ip2, _ := pool.Allocate()
    
    assert.Equal(t, "10.60.0.1", ip1.String())
    assert.Equal(t, "10.60.0.2", ip2.String())
}
```

### Mock UPF for Integration Testing
```go
type MockUPF struct {
    addr      *net.UDPAddr
    conn      *net.UDPConn
    responses chan []byte
}

func (m *MockUPF) Start() error {
    conn, err := net.ListenUDP("udp", m.addr)
    if err != nil {
        return err
    }
    m.conn = conn
    
    go m.handleMessages()
    return nil
}

func (m *MockUPF) handleMessages() {
    buffer := make([]byte, 4096)
    for {
        n, addr, _ := m.conn.ReadFromUDP(buffer)
        msg, _ := message.Parse(buffer[:n])
        
        // Generate appropriate response
        var response message.Message
        switch msg.MessageType() {
        case message.MsgTypeSessionEstablishmentRequest:
            req := msg.(*message.SessionEstablishmentRequest)
            remoteSEID := uint64(rand.Int63())
            response = message.NewSessionEstablishmentResponse(
                req.SequenceNumber,
                0, // No SEID in response
                ie.NewNodeID("", "", "upf.example.com"),
                ie.NewCause(ie.CauseRequestAccepted),
                ie.NewFSEID(remoteSEID, "192.168.1.20", ""),
            )
        }
        
        if response != nil {
            respBytes, _ := response.Marshal()
            m.conn.WriteToUDP(respBytes, addr)
        }
    }
}
```

## CLI Design

### Proposed Command Structure
```bash
# Basic usage
pfcp-generator --config config.yaml

# With overrides
pfcp-generator \
    --pcap capture.pcap \
    --smf-ip 192.168.1.10 \
    --upf-ip 192.168.1.20 \
    --ue-pool 10.60.0.0/24 \
    --seid-start 100 \
    --message-interval 100ms

# Dry run (parse only, don't send)
pfcp-generator --pcap capture.pcap --dry-run

# Verbose logging
pfcp-generator --config config.yaml --log-level debug

# Statistics only
pfcp-generator --config config.yaml --stats-only
```

### Expected Output
```
PFCP Message Generator v1.0.0
==============================
Config:
  SMF: 192.168.1.10:8805
  UPF: 192.168.1.20:8805
  PCAP: capture.pcap
  UE Pool: 10.60.0.0/24

Parsing PCAP...
Found 150 PFCP messages

Sending messages to UPF...
[✓] Association Setup Request → Response (seq=1)
[✓] Session Establishment Request → Response (seq=2, SEID=1→5001)
[✓] Session Modification Request → Response (seq=3)
[✓] Session Deletion Request → Response (seq=4)

Statistics:
  Total messages sent: 150
  Responses received: 150
  Errors: 0
  Sessions established: 50
  Duration: 15.2s
  Message rate: 9.9 msg/s
```

## Reference Links

- **3GPP TS 29.244**: PFCP Specification
  https://www.3gpp.org/ftp/Specs/archive/29_series/29.244/

- **wmnsk/go-pfcp GitHub**:
  https://github.com/wmnsk/go-pfcp

- **free5gc PFCP Implementation**:
  https://github.com/free5gc/pfcp

- **gopacket Documentation**:
  https://pkg.go.dev/github.com/google/gopacket
