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
	// Stress-mode scheduler state (written exclusively by the scheduler goroutine).
	TemplateIdx   int // index into PreEncodedTemplate slice
	ModsRemaining int // number of modifications left to send
	NextModIdx    int // index of the next mod to send in tmpl.ModMsgs
}

// TransactionResult holds the outcome of a PFCP transaction.
type TransactionResult struct {
	SeqNum       uint32
	Response     []byte
	ResponseTime time.Duration
	Error        error
	// Owner is set for transactions registered via TrackWith; carries the
	// originating session so the result collector needs no seq→session map.
	Owner *SessionInfo
	// MsgType is the request message type name (e.g. "SessionEstablishmentRequest").
	MsgType string
}

// SEIDMapping represents a mapping from original CP SEID to original remote (UP) SEID,
// extracted from Session Establishment Response messages in the pcap.
type SEIDMapping struct {
	OriginalCPSEID     uint64
	OriginalRemoteSEID uint64
}

// MessageStats holds per-message-type statistics.
type MessageStats struct {
	Sent       uint64
	Received   uint64
	Success    uint64
	Failed     uint64
	Timeout    uint64
	Retransmit uint64
}
