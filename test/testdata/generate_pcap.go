// +build ignore

// This program generates a sample PFCP pcap file for testing.
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func main() {
	filename := "test/testdata/sample.pcap"
	if len(os.Args) > 1 {
		filename = os.Args[1]
	}

	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		panic(err)
	}

	smfIP := net.ParseIP("192.168.1.10")
	upfIP := net.ParseIP("192.168.1.20")
	smfMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	upfMAC, _ := net.ParseMAC("66:77:88:99:aa:bb")
	ts := time.Now()

	seq := uint32(0)

	// Helper to write a PFCP packet as an Ethernet/IP/UDP frame
	writePacket := func(srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, pfcpData []byte, timestamp time.Time) {
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}
		udp := &layers.UDP{
			SrcPort: 8805,
			DstPort: 8805,
		}
		udp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		payload := gopacket.Payload(pfcpData)
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, payload); err != nil {
			panic(fmt.Sprintf("failed to serialize: %v", err))
		}

		ci := gopacket.CaptureInfo{
			Timestamp:     timestamp,
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		if err := w.WritePacket(ci, buf.Bytes()); err != nil {
			panic(fmt.Sprintf("failed to write packet: %v", err))
		}
	}

	marshalMsg := func(msg message.Message) []byte {
		b := make([]byte, msg.MarshalLen())
		if err := msg.MarshalTo(b); err != nil {
			panic(fmt.Sprintf("failed to marshal: %v", err))
		}
		return b
	}

	// === 1. Association Setup Request (SMF → UPF) ===
	seq++
	assocReq := message.NewAssociationSetupRequest(seq,
		ie.NewNodeID(smfIP.String(), "", ""),
		ie.NewRecoveryTimeStamp(ts),
		ie.NewCPFunctionFeatures(0),
	)
	writePacket(smfIP, upfIP, smfMAC, upfMAC, marshalMsg(assocReq), ts)
	ts = ts.Add(10 * time.Millisecond)

	// === 2. Association Setup Response (UPF → SMF) ===
	assocResp := message.NewAssociationSetupResponse(seq,
		ie.NewNodeID(upfIP.String(), "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(ts),
		ie.NewUPFunctionFeatures(0, 0),
	)
	writePacket(upfIP, smfIP, upfMAC, smfMAC, marshalMsg(assocResp), ts)
	ts = ts.Add(10 * time.Millisecond)

	// Generate 3 sessions
	type sessionSEIDs struct {
		cpSEID     uint64
		upSEID     uint64
		ueIPv4     string
	}
	sessions := []sessionSEIDs{
		{cpSEID: 1001, upSEID: 5001, ueIPv4: "10.60.0.1"},
		{cpSEID: 1002, upSEID: 5002, ueIPv4: "10.60.0.2"},
		{cpSEID: 1003, upSEID: 5003, ueIPv4: "10.60.0.3"},
	}

	for _, s := range sessions {
		// === Session Establishment Request (SMF → UPF) ===
		seq++
		estReq := message.NewSessionEstablishmentRequest(
			0, 0, // mp, fo
			0,    // SEID = 0 for establishment
			seq,
			0, // priority
			ie.NewNodeID(smfIP.String(), "", ""),
			ie.NewFSEID(s.cpSEID, smfIP, nil),
			ie.NewCreatePDR(
				ie.NewPDRID(1),
				ie.NewPrecedence(100),
				ie.NewPDI(
					ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewUEIPAddress(0x02, s.ueIPv4, "", 0, 0), // V4 only
					ie.NewNetworkInstance("internet"),
				),
				ie.NewFARID(1),
				ie.NewOuterHeaderRemoval(0, 0),
			),
			ie.NewCreatePDR(
				ie.NewPDRID(2),
				ie.NewPrecedence(100),
				ie.NewPDI(
					ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x06, s.ueIPv4, "", 0, 0), // V4 + SD(destination)
					ie.NewNetworkInstance("internet"),
				),
				ie.NewFARID(2),
			),
			ie.NewCreateFAR(
				ie.NewFARID(1),
				ie.NewApplyAction(0x02), // Forward
				ie.NewForwardingParameters(
					ie.NewDestinationInterface(ie.DstInterfaceCore),
					ie.NewNetworkInstance("internet"),
				),
			),
			ie.NewCreateFAR(
				ie.NewFARID(2),
				ie.NewApplyAction(0x02), // Forward
				ie.NewForwardingParameters(
					ie.NewDestinationInterface(ie.DstInterfaceAccess),
				),
			),
			ie.NewPDNType(ie.PDNTypeIPv4),
		)
		writePacket(smfIP, upfIP, smfMAC, upfMAC, marshalMsg(estReq), ts)
		ts = ts.Add(10 * time.Millisecond)

		// === Session Establishment Response (UPF → SMF) ===
		estResp := message.NewSessionEstablishmentResponse(
			0, 0,
			s.cpSEID, // SEID = CP SEID (sent back to SMF)
			seq,
			0,
			ie.NewNodeID(upfIP.String(), "", ""),
			ie.NewCause(ie.CauseRequestAccepted),
			ie.NewFSEID(s.upSEID, upfIP, nil),
		)
		writePacket(upfIP, smfIP, upfMAC, smfMAC, marshalMsg(estResp), ts)
		ts = ts.Add(10 * time.Millisecond)
	}

	// === Session Modification for session 1 ===
	seq++
	modReq := message.NewSessionModificationRequest(
		0, 0,
		sessions[0].upSEID, // Remote SEID (UPF's SEID)
		seq,
		0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(0x02),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x00000001, "10.0.0.1", "", 0, 0, 0),
			),
		),
	)
	writePacket(smfIP, upfIP, smfMAC, upfMAC, marshalMsg(modReq), ts)
	ts = ts.Add(10 * time.Millisecond)

	// === Session Modification Response ===
	modResp := message.NewSessionModificationResponse(
		0, 0,
		sessions[0].cpSEID,
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
	)
	writePacket(upfIP, smfIP, upfMAC, smfMAC, marshalMsg(modResp), ts)
	ts = ts.Add(10 * time.Millisecond)

	// === Session Deletion for session 1 ===
	seq++
	delReq := message.NewSessionDeletionRequest(
		0, 0,
		sessions[0].upSEID,
		seq,
		0,
	)
	writePacket(smfIP, upfIP, smfMAC, upfMAC, marshalMsg(delReq), ts)
	ts = ts.Add(10 * time.Millisecond)

	// === Session Deletion Response ===
	delResp := message.NewSessionDeletionResponse(
		0, 0,
		sessions[0].cpSEID,
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
	)
	writePacket(upfIP, smfIP, upfMAC, smfMAC, marshalMsg(delResp), ts)
	ts = ts.Add(10 * time.Millisecond)

	// === Heartbeat Request (SMF → UPF) ===
	seq++
	hbReq := message.NewHeartbeatRequest(seq,
		ie.NewRecoveryTimeStamp(ts),
		nil, // source IP IE (optional)
	)
	writePacket(smfIP, upfIP, smfMAC, upfMAC, marshalMsg(hbReq), ts)
	ts = ts.Add(10 * time.Millisecond)

	// === Heartbeat Response (UPF → SMF) ===
	hbResp := message.NewHeartbeatResponse(seq,
		ie.NewRecoveryTimeStamp(ts),
	)
	writePacket(upfIP, smfIP, upfMAC, smfMAC, marshalMsg(hbResp), ts)

	fmt.Printf("Generated %s with PFCP messages:\n", filename)
	fmt.Println("  1x Association Setup Request/Response")
	fmt.Println("  3x Session Establishment Request/Response")
	fmt.Println("  1x Session Modification Request/Response (session 1)")
	fmt.Println("  1x Session Deletion Request/Response (session 1)")
	fmt.Println("  1x Heartbeat Request/Response")
	fmt.Printf("  Total: 14 packets\n")
}
