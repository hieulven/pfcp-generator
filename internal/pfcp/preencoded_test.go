package pfcp

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// buildEstReq builds a minimal SessionEstablishmentRequest for testing.
func buildEstReq(cpSEID uint64, smfIP, ueIP net.IP) []byte {
	req := message.NewSessionEstablishmentRequest(
		0, 0, 0, 1, 0,
		ie.NewNodeID(smfIP.String(), "", ""),
		ie.NewFSEID(cpSEID, smfIP, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, ueIP.String(), "", 0, 0), // v4 flag = 0x02
			),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(0x0c),
		),
	)
	data, err := Encode(req)
	if err != nil {
		panic(err)
	}
	return data
}

func TestPreEncodeEstablishment_PatchesCorrectly(t *testing.T) {
	smfIP := net.ParseIP("10.0.0.1").To4()
	originalCPSEID := uint64(0xABCDEF0123456789)
	originalUEIP := net.ParseIP("10.60.0.1").To4()

	raw := buildEstReq(originalCPSEID, smfIP, originalUEIP)

	modifier := NewModifier(smfIP, true, false)
	pre, err := PreEncodeEstablishment(modifier, raw)
	require.NoError(t, err)
	require.NotNil(t, pre)

	// Patch offsets must be set
	assert.Equal(t, pfcpHeaderSEIDOffset, pre.HeaderSEIDOffset)
	assert.Equal(t, pfcpHeaderSeqOffset, pre.SeqOffset)
	assert.GreaterOrEqual(t, pre.CPFSEIDOffset, pfcpHeaderIEStart, "CP-FSEID offset should be within IE body")
	assert.NotEmpty(t, pre.UEIPv4Offsets, "should find at least one UE IP offset")

	// Apply patches and verify the resulting bytes decode correctly.
	newLocalSEID := uint64(0x1234567890ABCDEF)
	newUEIP := net.ParseIP("10.60.1.100").To4()
	newSeq := uint32(42)

	dst := make([]byte, len(pre.Data))
	pre.ApplyInto(dst, newSeq, 0, newLocalSEID, newUEIP)

	// Decode the patched bytes and check values.
	decoded, err := Decode(dst)
	require.NoError(t, err)

	estReq, ok := decoded.(*message.SessionEstablishmentRequest)
	require.True(t, ok)

	// Sequence number
	assert.Equal(t, newSeq, estReq.Sequence())

	// Header SEID should still be 0 for establishment
	assert.Equal(t, uint64(0), estReq.SEID())

	// CP-FSEID SEID should be patched with newLocalSEID
	require.NotNil(t, estReq.CPFSEID)
	fseid, err := estReq.CPFSEID.FSEID()
	require.NoError(t, err)
	assert.Equal(t, newLocalSEID, fseid.SEID)

	// UE IP should be patched
	require.NotEmpty(t, estReq.CreatePDR)
	// Verify at the byte level: check each discovered UE IP offset
	for _, off := range pre.UEIPv4Offsets {
		require.Greater(t, len(dst), off+3)
		assert.Equal(t, []byte(newUEIP), dst[off:off+4], "UE IP bytes at offset %d", off)
	}
}

func TestPreEncodeEstablishment_SeqNumEncoding(t *testing.T) {
	smfIP := net.ParseIP("10.0.0.1").To4()
	raw := buildEstReq(1, smfIP, net.ParseIP("10.0.0.2").To4())
	modifier := NewModifier(smfIP, true, false)

	pre, err := PreEncodeEstablishment(modifier, raw)
	require.NoError(t, err)

	// Test several sequence numbers including edge cases
	for _, seqNum := range []uint32{1, 0xFFFFFF, 0x800000, 42} {
		dst := make([]byte, len(pre.Data))
		pre.ApplyInto(dst, seqNum, 0, 1, net.ParseIP("10.0.0.2").To4())

		// Check seq bytes directly
		gotSeq := uint32(dst[pfcpHeaderSeqOffset])<<16 | uint32(dst[pfcpHeaderSeqOffset+1])<<8 | uint32(dst[pfcpHeaderSeqOffset+2])
		assert.Equal(t, seqNum&0xFFFFFF, gotSeq, "seq mismatch for seqNum=%d", seqNum)
	}
}

func TestPreEncodeModification_PatchesCorrectly(t *testing.T) {
	smfIP := net.ParseIP("10.0.0.1").To4()
	ueIP := net.ParseIP("10.60.0.1").To4()

	// Build a SessionModificationRequest with a CreatePDR carrying a UE IP.
	req := message.NewSessionModificationRequest(
		0, 0, 0x1234, 1, 0,
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(50),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewUEIPAddress(0x02, ueIP.String(), "", 0, 0),
			),
		),
	)
	raw, err := Encode(req)
	require.NoError(t, err)

	modifier := NewModifier(smfIP, true, false)
	pre, err := PreEncodeModification(modifier, raw)
	require.NoError(t, err)
	require.NotNil(t, pre)

	assert.Equal(t, -1, pre.CPFSEIDOffset, "modifications have no CP-FSEID")
	assert.NotEmpty(t, pre.UEIPv4Offsets)

	newRemoteSEID := uint64(0xDEADBEEF)
	newUEIP := net.ParseIP("10.60.2.50").To4()
	newSeq := uint32(99)

	dst := make([]byte, len(pre.Data))
	pre.ApplyInto(dst, newSeq, newRemoteSEID, 0, newUEIP)

	// Decode and verify
	decoded, err := Decode(dst)
	require.NoError(t, err)

	modReq, ok := decoded.(*message.SessionModificationRequest)
	require.True(t, ok)

	assert.Equal(t, newSeq, modReq.Sequence())
	assert.Equal(t, newRemoteSEID, modReq.SEID())

	// Verify SEID at byte level
	gotSEID := binary.BigEndian.Uint64(dst[pfcpHeaderSEIDOffset:])
	assert.Equal(t, newRemoteSEID, gotSEID)
}
