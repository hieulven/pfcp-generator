package pcap

import (
	"testing"

	pfcputil "pfcp-generator/internal/pfcp"
)

func TestParseLargePacketPcap(t *testing.T) {
	parser := NewParser()
	result, err := parser.ParseWithMappings("../../test/testdata/stard_trace.pcap")
	if err != nil {
		t.Fatalf("ParseWithMappings failed: %v", err)
	}

	if len(result.Messages) != 5 {
		t.Fatalf("Expected 5 request messages, got %d", len(result.Messages))
	}

	// Verify the large Session Establishment Request (4604 bytes PFCP payload)
	msg0, err := pfcputil.Decode(result.Messages[0].Data)
	if err != nil {
		t.Fatalf("Failed to decode message 0: %v", err)
	}
	if msg0.MessageType() != 50 { // SessionEstablishmentRequest
		t.Fatalf("Expected SessionEstablishmentRequest, got type %d", msg0.MessageType())
	}
	if len(result.Messages[0].Data) != 4604 {
		t.Fatalf("Expected 4604 bytes, got %d", len(result.Messages[0].Data))
	}

	if len(result.SEIDMappings) != 1 {
		t.Fatalf("Expected 1 SEID mapping, got %d", len(result.SEIDMappings))
	}

	// Verify message type counts
	counts, err := parser.CountMessages("../../test/testdata/stard_trace.pcap")
	if err != nil {
		t.Fatalf("CountMessages failed: %v", err)
	}

	expected := map[string]int{
		"SessionEstablishmentRequest":  1,
		"SessionEstablishmentResponse": 1,
		"SessionModificationRequest":   3,
		"SessionModificationResponse":  3,
		"SessionDeletionRequest":       1,
		"SessionDeletionResponse":      1,
	}
	for msgType, count := range expected {
		if counts[msgType] != count {
			t.Errorf("Expected %d %s, got %d", count, msgType, counts[msgType])
		}
	}
}

func TestFixPcapData(t *testing.T) {
	t.Run("returns unchanged data for non-pcap files", func(t *testing.T) {
		data := []byte("not a pcap file")
		result := fixPcapData(data)
		if &result[0] != &data[0] {
			t.Error("Expected same slice for non-pcap data")
		}
	})

	t.Run("returns unchanged data for short input", func(t *testing.T) {
		data := []byte{0xa1, 0xb2}
		result := fixPcapData(data)
		if len(result) != len(data) {
			t.Error("Expected same length")
		}
	})
}
