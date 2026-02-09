package types

import (
	"net"
	"time"
)

// RawPFCPMessage represents a raw PFCP message extracted from a pcap file.
type RawPFCPMessage struct {
	Data      []byte
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
}

// SessionInfo holds the state of a single PFCP session.
type SessionInfo struct {
	OriginalCPSEID     uint64    // CP SEID from pcap (F-SEID IE in Establishment Request)
	OriginalRemoteSEID uint64    // Remote SEID from pcap (header SEID in Modification/Deletion)
	LocalSEID          uint64    // Newly allocated CP SEID
	RemoteSEID         uint64    // UP SEID from UPF response
	UEIP               net.IP    // Allocated UE IP
	State              string    // "establishing", "established", "modifying", "deleting", "deleted"
	CreatedAt          time.Time
}

// TransactionResult holds the outcome of a PFCP transaction.
type TransactionResult struct {
	SeqNum       uint32
	Response     []byte
	ResponseTime time.Duration
	Error        error
}

// SEIDMapping represents a mapping from original CP SEID to original remote (UP) SEID,
// extracted from Session Establishment Response messages in the pcap.
type SEIDMapping struct {
	OriginalCPSEID     uint64
	OriginalRemoteSEID uint64
}

// MessageStats holds per-message-type statistics.
type MessageStats struct {
	Sent         uint64
	Received     uint64
	Success      uint64
	Failed       uint64
	Timeout      uint64
	Retransmit   uint64
}
