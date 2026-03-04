package pcap

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", filename, err)
	}
	defer handle.Close()

	linkType := handle.LinkType()
	log.WithField("link_type", linkType.String()).Debug("PCAP link type detected")

	packetSource := gopacket.NewPacketSource(handle, linkType)
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

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
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", filename, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	counts := make(map[string]int)

	for packet := range packetSource.Packets() {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}

		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
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
