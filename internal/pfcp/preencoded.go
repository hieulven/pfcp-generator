package pfcp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/wmnsk/go-pfcp/message"
)

// PFCP header offsets for session-level messages (S flag set, SEID present).
const (
	pfcpHeaderSEIDOffset = 4  // 8-byte SEID starts here
	pfcpHeaderSeqOffset  = 12 // 3-byte sequence number starts here
	pfcpHeaderIEStart    = 16 // IEs start here
)

// IE type constants used for scanning encoded PFCP messages.
const (
	ieTypeFSEID       = 57 // F-SEID (CP-FSEID in establishment)
	ieTypeCreatePDR   = 1
	ieTypeUpdatePDR   = 9
	ieTypePDI         = 2
	ieTypeUEIPAddress = 93
)

// PreEncodedMsg is a PFCP message pre-encoded to bytes with byte offsets for
// the per-session variable fields. At send time, copy the Data bytes and apply
// patches rather than decode → modify → encode.
type PreEncodedMsg struct {
	Data []byte

	// SeqOffset is the byte offset of the 3-byte sequence number field.
	SeqOffset int

	// HeaderSEIDOffset is the byte offset of the 8-byte SEID in the PFCP header.
	// Set to -1 if the message has no SEID in the header.
	HeaderSEIDOffset int

	// CPFSEIDOffset is the byte offset of the 8-byte SEID within the CP-FSEID IE value.
	// Set to -1 if the message has no CP-FSEID IE.
	CPFSEIDOffset int

	// UEIPv4Offsets are the byte offsets of each 4-byte UE IPv4 address found
	// within UE IP Address IEs (there may be multiple, one per PDR).
	UEIPv4Offsets []int
}

// ApplyInto copies Data into dst (which must have len == len(Data)) and patches
// the variable fields. Pass headerSEID=0 for establishment requests (already 0 in template).
func (p *PreEncodedMsg) ApplyInto(dst []byte, seqNum uint32, headerSEID uint64, cpfseidSEID uint64, ueIP net.IP) {
	copy(dst, p.Data)

	// Sequence number: 3 bytes, big-endian
	dst[p.SeqOffset] = byte(seqNum >> 16)
	dst[p.SeqOffset+1] = byte(seqNum >> 8)
	dst[p.SeqOffset+2] = byte(seqNum)

	// Header SEID: 8 bytes
	if p.HeaderSEIDOffset >= 0 {
		binary.BigEndian.PutUint64(dst[p.HeaderSEIDOffset:], headerSEID)
	}

	// CP-FSEID SEID: 8 bytes
	if p.CPFSEIDOffset >= 0 {
		binary.BigEndian.PutUint64(dst[p.CPFSEIDOffset:], cpfseidSEID)
	}

	// UE IP: 4 bytes at each discovered offset
	if len(p.UEIPv4Offsets) > 0 && ueIP != nil {
		if v4 := ueIP.To4(); v4 != nil {
			for _, off := range p.UEIPv4Offsets {
				copy(dst[off:], v4)
			}
		}
	}
}

// PreEncodeEstablishment pre-encodes a Session Establishment Request template.
// It applies all constant modifications (vendor IE stripping, Node ID, etc.) with
// placeholder session-specific values, then finds the patch offsets for the fields
// that vary per session: CP-FSEID SEID, UE IP, and sequence number.
func PreEncodeEstablishment(modifier *Modifier, raw []byte) (*PreEncodedMsg, error) {
	msg, err := Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	req, ok := msg.(*message.SessionEstablishmentRequest)
	if !ok {
		return nil, fmt.Errorf("expected SessionEstablishmentRequest, got %T", msg)
	}

	// Apply all constant modifications with placeholder values.
	// localSEID=0 (header stays 0 for establishment, CP-FSEID SEID will be patched),
	// ueIP=192.0.2.1 (TEST-NET, distinctive placeholder for offset validation),
	// seqNum=0 (will always be patched before send).
	placeholderIP := net.ParseIP("192.0.2.1").To4()
	if err := modifier.ModifySessionEstablishment(req, 0, placeholderIP, 0); err != nil {
		return nil, fmt.Errorf("modify: %w", err)
	}

	data, err := Encode(req)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	if len(data) < pfcpHeaderIEStart {
		return nil, fmt.Errorf("encoded message too short: %d bytes", len(data))
	}

	cpfseidOff, ueIPOffsets := scanForPatchOffsets(data, pfcpHeaderIEStart)

	pre := &PreEncodedMsg{
		Data:             data,
		SeqOffset:        pfcpHeaderSeqOffset,
		HeaderSEIDOffset: pfcpHeaderSEIDOffset,
		CPFSEIDOffset:    cpfseidOff,
		UEIPv4Offsets:    ueIPOffsets,
	}

	// Validate: confirm placeholder IP appears at each discovered UE IP offset.
	for _, off := range ueIPOffsets {
		if off+4 > len(data) {
			return nil, fmt.Errorf("UE IP offset %d out of bounds (msg len %d)", off, len(data))
		}
		if data[off] != placeholderIP[0] || data[off+1] != placeholderIP[1] ||
			data[off+2] != placeholderIP[2] || data[off+3] != placeholderIP[3] {
			return nil, fmt.Errorf("UE IP offset %d validation failed: got %v, want %v",
				off, data[off:off+4], []byte(placeholderIP))
		}
	}

	return pre, nil
}

// PreEncodeModification pre-encodes a Session Modification Request template.
// Variable fields per session: header SEID (remoteSEID), UE IP (if CreatePDR/UpdatePDR present),
// and sequence number.
func PreEncodeModification(modifier *Modifier, raw []byte) (*PreEncodedMsg, error) {
	msg, err := Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	req, ok := msg.(*message.SessionModificationRequest)
	if !ok {
		return nil, fmt.Errorf("expected SessionModificationRequest, got %T", msg)
	}

	// Apply constant modifications with placeholder values.
	// remoteSEID=0 (will be patched per session),
	// ueIP=192.0.2.1 (distinctive placeholder, will be patched per session).
	placeholderIP := net.ParseIP("192.0.2.1").To4()
	if err := modifier.ModifySessionModification(req, 0, placeholderIP, 0); err != nil {
		return nil, fmt.Errorf("modify: %w", err)
	}

	data, err := Encode(req)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	if len(data) < pfcpHeaderIEStart {
		return nil, fmt.Errorf("encoded message too short: %d bytes", len(data))
	}

	_, ueIPOffsets := scanForPatchOffsets(data, pfcpHeaderIEStart)

	return &PreEncodedMsg{
		Data:             data,
		SeqOffset:        pfcpHeaderSeqOffset,
		HeaderSEIDOffset: pfcpHeaderSEIDOffset,
		CPFSEIDOffset:    -1, // modifications do not carry CP-FSEID
		UEIPv4Offsets:    ueIPOffsets,
	}, nil
}

// scanForPatchOffsets scans TLV-encoded PFCP IEs starting at ieStart and returns:
//   - the byte offset of the 8-byte SEID field within the first F-SEID IE value (-1 if absent)
//   - the byte offsets of each 4-byte IPv4 field within UE IP Address IEs
func scanForPatchOffsets(data []byte, ieStart int) (cpfseidSEIDOffset int, ueIPv4Offsets []int) {
	cpfseidSEIDOffset = -1
	n := len(data)

	for off := ieStart; off+4 <= n; {
		ieType := int(data[off])<<8 | int(data[off+1])
		ieLen := int(data[off+2])<<8 | int(data[off+3])
		valOff := off + 4

		if valOff+ieLen > n {
			break
		}

		switch ieType {
		case ieTypeFSEID:
			// F-SEID value: [flags(1)] [SEID(8)] [IPv4(4)?] [IPv6(16)?]
			if cpfseidSEIDOffset == -1 && ieLen >= 9 {
				cpfseidSEIDOffset = valOff + 1 // skip flags byte
			}

		case ieTypeCreatePDR, ieTypeUpdatePDR:
			scanPDR(data, valOff, valOff+ieLen, &ueIPv4Offsets)
		}

		off = valOff + ieLen
	}
	return
}

// scanPDR scans a Create/Update PDR grouped IE for PDI → UE IP Address IEs.
func scanPDR(data []byte, start, end int, ueIPOffsets *[]int) {
	for off := start; off+4 <= end; {
		ieType := int(data[off])<<8 | int(data[off+1])
		ieLen := int(data[off+2])<<8 | int(data[off+3])
		valOff := off + 4

		if valOff+ieLen > end {
			break
		}

		if ieType == ieTypePDI {
			scanPDI(data, valOff, valOff+ieLen, ueIPOffsets)
		}

		off = valOff + ieLen
	}
}

// scanPDI scans a PDI grouped IE for UE IP Address IEs.
func scanPDI(data []byte, start, end int, ueIPOffsets *[]int) {
	for off := start; off+4 <= end; {
		ieType := int(data[off])<<8 | int(data[off+1])
		ieLen := int(data[off+2])<<8 | int(data[off+3])
		valOff := off + 4

		if valOff+ieLen > end {
			break
		}

		// UE IP Address value: [flags(1)] [IPv4(4)?] [IPv6(16)?]
		if ieType == ieTypeUEIPAddress && ieLen >= 5 {
			ueIPv4Off := valOff + 1 // skip flags byte
			// Only record if v4 flag is set (bit 1 of flags byte = 0x02 in go-pfcp encoding)
			if data[valOff]&0x02 != 0 {
				*ueIPOffsets = append(*ueIPOffsets, ueIPv4Off)
			}
		}

		off = valOff + ieLen
	}
}
