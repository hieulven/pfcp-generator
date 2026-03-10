package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"

	pfcputil "pfcp-generator/internal/pfcp"
	"pfcp-generator/pkg/types"
)

// Parser reads PCAP files and extracts PFCP request messages.
type Parser struct{}

// NewParser creates a new PCAP parser.
func NewParser() *Parser {
	return &Parser{}
}

// pcap magic numbers
const (
	pcapMagicLE   = 0xa1b2c3d4 // little-endian microseconds
	pcapMagicBE   = 0xd4c3b2a1 // big-endian microseconds
	pcapMagicNsLE = 0xa1b23c4d // little-endian nanoseconds
	pcapMagicNsBE = 0x4d3cb2a1 // big-endian nanoseconds
)

// fixPcapData reads a pcap file and fixes common issues:
// 1. Snaplen too small: if any packet's captured length exceeds the declared snaplen,
//    the snaplen is increased. This handles pcap files captured on virtual interfaces
//    (e.g., Linux cooked capture with GRO/GSO).
// 2. Corrupt SLL headers: if the link type is Linux SLL (113) and a packet has an
//    invalid address length (halen > 8), it is clamped to 8. The SLL v1 address field
//    is always 8 bytes, so halen values larger than 8 cause gopacket to panic.
func fixPcapData(data []byte) []byte {
	if len(data) < 24 {
		return data
	}

	magic := binary.LittleEndian.Uint32(data[0:4])

	var bo binary.ByteOrder
	switch magic {
	case pcapMagicLE, pcapMagicNsLE:
		bo = binary.LittleEndian
	case pcapMagicBE, pcapMagicNsBE:
		bo = binary.BigEndian
	default:
		// Not a pcap file (might be pcapng), return unchanged
		return data
	}

	snaplen := bo.Uint32(data[16:20])
	linkType := bo.Uint32(data[20:24])
	isSLL := linkType == 113 // LINKTYPE_LINUX_SLL

	// Scan packet records to find max captured length and detect SLL issues
	var maxInclLen uint32
	needsFix := false
	offset := 24
	for offset+16 <= len(data) {
		inclLen := bo.Uint32(data[offset+8 : offset+12])
		if inclLen > maxInclLen {
			maxInclLen = inclLen
		}
		// Check for corrupt SLL halen (bytes 4-5 of packet data, big-endian)
		pktDataStart := offset + 16
		if isSLL && int(inclLen) >= 16 && pktDataStart+6 <= len(data) {
			halen := binary.BigEndian.Uint16(data[pktDataStart+4 : pktDataStart+6])
			if halen > 8 {
				needsFix = true
			}
		}
		offset += 16 + int(inclLen)
	}

	if maxInclLen > snaplen {
		needsFix = true
	}

	if !needsFix {
		return data
	}

	// Make a copy and apply fixes
	fixed := make([]byte, len(data))
	copy(fixed, data)

	if maxInclLen > snaplen {
		log.WithFields(log.Fields{
			"old_snaplen":  snaplen,
			"max_pkt_size": maxInclLen,
			"new_snaplen":  maxInclLen,
		}).Debug("Fixing pcap snaplen to accommodate large packets")
		bo.PutUint32(fixed[16:20], maxInclLen)
	}

	// Fix corrupt SLL headers
	if isSLL {
		offset = 24
		for offset+16 <= len(fixed) {
			inclLen := bo.Uint32(fixed[offset+8 : offset+12])
			pktDataStart := offset + 16
			if int(inclLen) >= 16 && pktDataStart+6 <= len(fixed) {
				halen := binary.BigEndian.Uint16(fixed[pktDataStart+4 : pktDataStart+6])
				if halen > 8 {
					log.WithFields(log.Fields{
						"offset": pktDataStart,
						"halen":  halen,
					}).Debug("Fixing corrupt SLL address length")
					binary.BigEndian.PutUint16(fixed[pktDataStart+4:pktDataStart+6], 8)
				}
			}
			offset += 16 + int(inclLen)
		}
	}

	return fixed
}

// openPcapFile reads a pcap/pcapng file and returns a PacketDataSource and link type.
// It automatically fixes snaplen mismatches in pcap files.
func openPcapFile(filename string) (gopacket.PacketDataSource, layers.LinkType, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read pcap file %s: %w", filename, err)
	}

	data = fixPcapData(data)

	// Try pcap format first
	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err == nil {
		linkType := reader.LinkType()
		log.WithField("link_type", linkType.String()).Debug("PCAP link type detected")
		return reader, linkType, nil
	}
	pcapErr := err

	// Try pcapng format
	ngReader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
	if err == nil {
		linkType := ngReader.LinkType()
		log.WithField("link_type", linkType.String()).Debug("PCAP link type detected (pcapng)")
		return ngReader, linkType, nil
	}

	return nil, 0, fmt.Errorf("failed to open pcap file %s (pcap: %v, pcapng: %v)", filename, pcapErr, err)
}

// defragAndGetUDP extracts the UDP layer from a packet, transparently reassembling IPv4 fragments.
// Returns nil UDP when the packet is not UDP/8805-bound, or when a fragment is stored awaiting peers.
func defragAndGetUDP(packet gopacket.Packet, defragger *ip4defrag.IPv4Defragmenter) (udp *layers.UDP, srcIP, dstIP net.IP) {
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		srcIP = ip4.SrcIP
		dstIP = ip4.DstIP

		reassembled, err := defragger.DefragIPv4(ip4)
		if err != nil {
			log.WithError(err).Debug("IPv4 defrag error")
			return nil, nil, nil
		}
		if reassembled == nil {
			// Fragment stored, waiting for remaining fragments
			return nil, nil, nil
		}

		// Decode the transport layer from the (possibly reassembled) payload.
		// For non-fragmented packets DefragIPv4 returns the original ip4 immediately.
		inner := gopacket.NewPacket(reassembled.Payload, reassembled.NextLayerType(), gopacket.Default)
		if udpL := inner.Layer(layers.LayerTypeUDP); udpL != nil {
			udp, _ = udpL.(*layers.UDP)
		}
		return

	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		// IPv6 fragment reassembly is not implemented; fall back to direct decode.
		ip6 := ip6Layer.(*layers.IPv6)
		srcIP = ip6.SrcIP
		dstIP = ip6.DstIP
		if udpL := packet.Layer(layers.LayerTypeUDP); udpL != nil {
			udp, _ = udpL.(*layers.UDP)
		}
		return
	}

	return nil, nil, nil
}

// ParseResult contains the parsed PFCP request messages and SEID mappings from the pcap.
type ParseResult struct {
	Messages     []types.RawPFCPMessage
	SEIDMappings []types.SEIDMapping // original CP SEID → original remote (UP) SEID
}

// Parse reads a pcap file and returns all PFCP request messages in order,
// along with SEID mappings extracted from Session Establishment Response messages.
func (p *Parser) Parse(filename string) ([]types.RawPFCPMessage, error) {
	result, err := p.ParseWithMappings(filename)
	if err != nil {
		return nil, err
	}
	return result.Messages, nil
}

// ParseWithMappings reads a pcap file and returns request messages plus SEID mappings.
func (p *Parser) ParseWithMappings(filename string) (*ParseResult, error) {
	source, linkType, err := openPcapFile(filename)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(source, linkType)

	result := &ParseResult{}
	defragger := ip4defrag.NewIPv4Defragmenter()
	totalPackets := 0
	pfcpPackets := 0
	requestPackets := 0

	for packet := range packetSource.Packets() {
		totalPackets++

		udp, srcIP, dstIP := defragAndGetUDP(packet, defragger)
		if udp == nil {
			continue
		}

		// Filter PFCP port (8805)
		if udp.DstPort != 8805 && udp.SrcPort != 8805 {
			continue
		}

		payload := udp.Payload
		if len(payload) == 0 {
			continue
		}

		pfcpPackets++

		// Parse PFCP message to check if it's a request
		msg, err := pfcputil.Decode(payload)
		if err != nil {
			log.WithError(err).WithField("packet", totalPackets).Warn("Failed to decode PFCP message, skipping")
			continue
		}

		// Extract SEID mappings from Session Establishment Responses
		if resp, ok := msg.(*message.SessionEstablishmentResponse); ok {
			if resp.UPFSEID != nil {
				fseid, err := resp.UPFSEID.FSEID()
				if err == nil {
					cpSEID := resp.SEID() // header SEID = original CP SEID
					mapping := types.SEIDMapping{
						OriginalCPSEID:     cpSEID,
						OriginalRemoteSEID: fseid.SEID,
					}
					result.SEIDMappings = append(result.SEIDMappings, mapping)
					log.WithFields(log.Fields{
						"packet":      totalPackets,
						"cp_seid":     cpSEID,
						"remote_seid": fseid.SEID,
					}).Debug("Extracted SEID mapping from Establishment Response")
				}
			}
		}

		// Only keep request messages (skip responses)
		if !pfcputil.IsRequest(msg) {
			log.WithFields(log.Fields{
				"packet":   totalPackets,
				"msg_type": pfcputil.MessageTypeName(msg.MessageType()),
			}).Debug("Skipping response message")
			continue
		}

		requestPackets++

		// Copy payload (inner packet from defrag has its own allocation, but copy for safety)
		dataCopy := make([]byte, len(payload))
		copy(dataCopy, payload)

		rawMsg := types.RawPFCPMessage{
			Data:      dataCopy,
			Timestamp: packet.Metadata().Timestamp,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   uint16(udp.SrcPort),
			DstPort:   uint16(udp.DstPort),
		}

		result.Messages = append(result.Messages, rawMsg)

		log.WithFields(log.Fields{
			"packet":   totalPackets,
			"msg_type": pfcputil.MessageTypeName(msg.MessageType()),
			"src":      fmt.Sprintf("%s:%d", srcIP, udp.SrcPort),
			"dst":      fmt.Sprintf("%s:%d", dstIP, udp.DstPort),
		}).Debug("Extracted PFCP request")
	}

	log.WithFields(log.Fields{
		"total_packets":   totalPackets,
		"pfcp_packets":    pfcpPackets,
		"request_packets": requestPackets,
	}).Info("PCAP parsing complete")

	return result, nil
}

// CountMessages returns a summary of message types found in a pcap file.
func (p *Parser) CountMessages(filename string) (map[string]int, error) {
	source, linkType, err := openPcapFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", filename, err)
	}

	packetSource := gopacket.NewPacketSource(source, linkType)
	counts := make(map[string]int)
	defragger := ip4defrag.NewIPv4Defragmenter()

	for packet := range packetSource.Packets() {
		udp, _, _ := defragAndGetUDP(packet, defragger)
		if udp == nil {
			continue
		}

		if udp.DstPort != 8805 && udp.SrcPort != 8805 {
			continue
		}

		if len(udp.Payload) == 0 {
			continue
		}

		msg, err := pfcputil.Decode(udp.Payload)
		if err != nil {
			continue
		}

		counts[pfcputil.MessageTypeName(msg.MessageType())]++
	}

	return counts, nil
}

// ValidateHasEstablishment checks that the pcap contains at least one Session Establishment Request.
func (p *Parser) ValidateHasEstablishment(messages []types.RawPFCPMessage) error {
	for _, raw := range messages {
		msg, err := pfcputil.Decode(raw.Data)
		if err != nil {
			continue
		}
		if msg.MessageType() == 50 { // SessionEstablishmentRequest
			return nil
		}
	}
	return fmt.Errorf("pcap file does not contain any Session Establishment Request messages")
}

// HasDeletionRequests checks if the pcap contains Session Deletion Request messages.
func (p *Parser) HasDeletionRequests(messages []types.RawPFCPMessage) bool {
	for _, raw := range messages {
		msg, err := pfcputil.Decode(raw.Data)
		if err != nil {
			continue
		}
		if msg.MessageType() == 54 { // SessionDeletionRequest
			return true
		}
	}
	return false
}

// Unused but keeping for timestamp reference
var _ = time.Now
