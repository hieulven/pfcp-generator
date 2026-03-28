package pfcp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func TestModifySessionDeletion_StripsVendorIEs(t *testing.T) {
	mod := NewModifier(net.ParseIP("10.0.0.1"), true, true)

	// Create a deletion request with a vendor-specific IE (type 32769)
	vendorIE := ie.New(32769, []byte{0x01, 0x02})
	req := message.NewSessionDeletionRequest(0, 0, 100, 1, 0, vendorIE)

	require.Len(t, req.IEs, 1, "should have 1 IE before modification")

	err := mod.ModifySessionDeletion(req, 200, 42)
	require.NoError(t, err)

	assert.Equal(t, uint64(200), req.SEID())
	assert.Equal(t, uint32(42), req.Sequence())
	assert.Empty(t, req.IEs, "vendor IEs should be stripped")
}

func TestModifySessionDeletion_PreservesStandardIEs(t *testing.T) {
	mod := NewModifier(net.ParseIP("10.0.0.1"), true, true)

	standardIE := ie.NewCause(ie.CauseRequestAccepted)
	vendorIE := ie.New(32769, []byte{0x01})
	req := message.NewSessionDeletionRequest(0, 0, 100, 1, 0, standardIE, vendorIE)

	require.Len(t, req.IEs, 2)

	err := mod.ModifySessionDeletion(req, 200, 42)
	require.NoError(t, err)

	assert.Len(t, req.IEs, 1, "should keep standard IE, strip vendor IE")
	assert.Equal(t, ie.Cause, req.IEs[0].Type)
}

func TestModifySessionDeletion_NoStripWhenDisabled(t *testing.T) {
	mod := NewModifier(net.ParseIP("10.0.0.1"), true, false) // stripVendorIEs=false

	vendorIE := ie.New(32769, []byte{0x01})
	req := message.NewSessionDeletionRequest(0, 0, 100, 1, 0, vendorIE)

	err := mod.ModifySessionDeletion(req, 200, 42)
	require.NoError(t, err)

	assert.Len(t, req.IEs, 1, "vendor IE should be preserved when stripping is disabled")
}
