package test

import (
	"fmt"
	"net"
	"testing"

	"pfcp-generator/internal/pcap"
	"pfcp-generator/internal/pfcp"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func TestStressModifyRoundTrip(t *testing.T) {
	parser := pcap.NewParser()
	result, err := parser.ParseWithMappings("../test/testdata/stard_trace.pcap")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	modifier := pfcp.NewModifier(net.ParseIP("127.0.0.1"), true, true)

	for i, raw := range result.Messages {
		msg, err := pfcp.Decode(raw.Data)
		if err != nil {
			t.Fatalf("decode msg %d: %v", i, err)
		}

		est, ok := msg.(*message.SessionEstablishmentRequest)
		if !ok {
			continue
		}

		fmt.Printf("\n=== Session Establishment Request (msg %d) ===\n", i)
		fmt.Printf("Original raw size: %d bytes\n", len(raw.Data))

		// Print all top-level IEs before modification
		fmt.Println("\nBefore modification:")
		printIETree(est.CreatePDR, "CreatePDR")

		// Count top-level IEs via re-parse
		origMsg, _ := message.Parse(raw.Data)
		if origEst, ok := origMsg.(*message.SessionEstablishmentRequest); ok {
			fmt.Printf("\nTop-level IE count: NodeID=%v CPFSEID=%v CreatePDR=%d CreateFAR=%d CreateURR=%d CreateQER=%d\n",
				origEst.NodeID != nil, origEst.CPFSEID != nil,
				len(origEst.CreatePDR), len(origEst.CreateFAR),
				len(origEst.CreateURR), len(origEst.CreateQER))

			// Check for vendor IEs (type >= 32768)
			// Re-parse raw to get all IEs including unrecognized ones
			fmt.Println("\nLooking for vendor/unknown IEs in CreatePDR children:")
			for j, pdr := range origEst.CreatePDR {
				fmt.Printf("  PDR[%d] type=%d childIEs=%d marshalLen=%d\n", j, pdr.Type, len(pdr.ChildIEs), pdr.MarshalLen())
				for k, child := range pdr.ChildIEs {
					if child.Type >= 32768 || child.Type == 0 {
						fmt.Printf("    VENDOR/UNKNOWN IE[%d]: type=%d len=%d\n", k, child.Type, child.Length)
					}
				}
				// Check PDI children too
				for _, child := range pdr.ChildIEs {
					if child.Type == ie.PDI {
						for _, pdiChild := range child.ChildIEs {
							if pdiChild.Type >= 32768 || pdiChild.Type == 0 {
								fmt.Printf("    PDI VENDOR/UNKNOWN IE: type=%d len=%d\n", pdiChild.Type, pdiChild.Length)
							}
						}
					}
				}
			}
		}

		// Now modify
		err = modifier.ModifySessionEstablishment(est, 42, net.ParseIP("10.60.0.1"), uint32(i+1))
		if err != nil {
			t.Fatalf("modify: %v", err)
		}

		encoded, err := pfcp.Encode(msg)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		fmt.Printf("\nAfter modification: %d bytes (diff=%d)\n", len(encoded), len(encoded)-len(raw.Data))

		// Re-parse modified
		modMsg, _ := message.Parse(encoded)
		if modEst, ok := modMsg.(*message.SessionEstablishmentRequest); ok {
			fmt.Println("\nAfter modification:")
			printIETree(modEst.CreatePDR, "CreatePDR")

			fmt.Printf("\nModified top-level IE count: NodeID=%v CPFSEID=%v CreatePDR=%d CreateFAR=%d CreateURR=%d CreateQER=%d\n",
				modEst.NodeID != nil, modEst.CPFSEID != nil,
				len(modEst.CreatePDR), len(modEst.CreateFAR),
				len(modEst.CreateURR), len(modEst.CreateQER))
		}
	}
}

func printIETree(pdrs []*ie.IE, label string) {
	for j, pdr := range pdrs {
		fmt.Printf("  %s[%d]: type=%d childIEs=%d marshalLen=%d\n", label, j, pdr.Type, len(pdr.ChildIEs), pdr.MarshalLen())
		for _, child := range pdr.ChildIEs {
			name := ieTypeName(child.Type)
			fmt.Printf("    IE type=%d (%s) len=%d children=%d\n", child.Type, name, child.Length, len(child.ChildIEs))
		}
	}
}

func ieTypeName(t uint16) string {
	names := map[uint16]string{
		1: "CreatePDR", 2: "PDI", 3: "CreateFAR", 6: "UpdateFAR",
		9: "UpdatePDR", 20: "SourceInterface", 21: "F-TEID",
		22: "NetworkInstance", 23: "SDFFilter", 29: "Precedence",
		56: "PDR-ID", 57: "F-SEID", 60: "NodeID",
		81: "URR-ID", 84: "OuterHeaderCreation", 93: "UEIPAddress",
		95: "OuterHeaderRemoval", 106: "ActivatePredefRules",
		108: "FAR-ID", 109: "QER-ID", 124: "QFI",
	}
	if t >= 32768 {
		return fmt.Sprintf("VENDOR-%d", t)
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("unknown-%d", t)
}
