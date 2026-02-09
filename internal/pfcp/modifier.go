package pfcp

import (
	"fmt"
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// Modifier applies session-specific modifications to PFCP messages.
type Modifier struct {
	smfIP     net.IP
	stripIPv6 bool
}

// NewModifier creates a new PFCP message modifier.
func NewModifier(smfIP net.IP, stripIPv6 bool) *Modifier {
	return &Modifier{
		smfIP:     smfIP,
		stripIPv6: stripIPv6,
	}
}

// ModifyAssociationSetup updates the sequence number and optionally the Node ID.
func (m *Modifier) ModifyAssociationSetup(msg *message.AssociationSetupRequest, seqNum uint32) error {
	msg.Header.SetSequenceNumber(seqNum)

	// Update Node ID to use our SMF IP if configured
	if m.smfIP != nil && msg.NodeID != nil {
		if m.smfIP.To4() != nil {
			msg.NodeID = ie.NewNodeID(m.smfIP.String(), "", "")
		} else {
			msg.NodeID = ie.NewNodeID("", m.smfIP.String(), "")
		}
	}

	return nil
}

// ModifySessionEstablishment replaces F-SEID, UE IP, header SEID, and sequence number.
func (m *Modifier) ModifySessionEstablishment(
	msg *message.SessionEstablishmentRequest,
	localSEID uint64,
	ueIP net.IP,
	seqNum uint32,
) error {
	// Set header SEID to 0 for initial establishment
	msg.Header.SetSEID(0)
	msg.Header.SetSequenceNumber(seqNum)

	// Replace CP F-SEID with our local SEID and SMF IP
	if msg.CPFSEID != nil {
		var v4, v6 net.IP
		if m.smfIP != nil {
			if m.smfIP.To4() != nil {
				v4 = m.smfIP
			} else {
				v6 = m.smfIP
			}
		} else {
			// Try to preserve original IP version from existing F-SEID
			fseid, err := msg.CPFSEID.FSEID()
			if err == nil {
				v4 = fseid.IPv4Address
				v6 = fseid.IPv6Address
			}
		}
		msg.CPFSEID = ie.NewFSEID(localSEID, v4, v6)
	}

	// Replace UE IP Address in Create PDR → PDI
	if err := m.modifyUEIPInCreatePDRs(msg.CreatePDR, ueIP); err != nil {
		return fmt.Errorf("failed to modify UE IP in Create PDRs: %w", err)
	}

	// Also update Node ID
	if m.smfIP != nil && msg.NodeID != nil {
		if m.smfIP.To4() != nil {
			msg.NodeID = ie.NewNodeID(m.smfIP.String(), "", "")
		} else {
			msg.NodeID = ie.NewNodeID("", m.smfIP.String(), "")
		}
	}

	return nil
}

// ModifySessionModification updates the header SEID and sequence number.
func (m *Modifier) ModifySessionModification(
	msg *message.SessionModificationRequest,
	remoteSEID uint64,
	ueIP net.IP,
	seqNum uint32,
) error {
	msg.Header.SetSEID(remoteSEID)
	msg.Header.SetSequenceNumber(seqNum)

	// If there are new Create PDRs in the modification, update UE IP
	if len(msg.CreatePDR) > 0 && ueIP != nil {
		if err := m.modifyUEIPInCreatePDRs(msg.CreatePDR, ueIP); err != nil {
			return fmt.Errorf("failed to modify UE IP in Create PDRs: %w", err)
		}
	}

	// Also modify UE IP in Update PDRs if present
	if len(msg.UpdatePDR) > 0 && ueIP != nil {
		if err := m.modifyUEIPInCreatePDRs(msg.UpdatePDR, ueIP); err != nil {
			return fmt.Errorf("failed to modify UE IP in Update PDRs: %w", err)
		}
	}

	return nil
}

// ModifySessionDeletion updates the header SEID and sequence number.
func (m *Modifier) ModifySessionDeletion(
	msg *message.SessionDeletionRequest,
	remoteSEID uint64,
	seqNum uint32,
) error {
	msg.Header.SetSEID(remoteSEID)
	msg.Header.SetSequenceNumber(seqNum)
	return nil
}

// ModifyHeartbeat updates the sequence number on a heartbeat request.
func (m *Modifier) ModifyHeartbeat(msg *message.HeartbeatRequest, seqNum uint32) error {
	msg.Header.SetSequenceNumber(seqNum)
	return nil
}

// modifyUEIPInCreatePDRs finds and replaces UE IP Address IEs within Create/Update PDR IEs.
func (m *Modifier) modifyUEIPInCreatePDRs(pdrs []*ie.IE, newUEIP net.IP) error {
	for i, pdr := range pdrs {
		if pdr == nil {
			continue
		}
		modified, err := m.modifyUEIPInPDR(pdr, newUEIP)
		if err != nil {
			continue // PDR may not have UE IP, that's OK
		}
		if modified != nil {
			pdrs[i] = modified
		}
	}
	return nil
}

// modifyUEIPInPDR modifies the UE IP Address IE within a single PDR IE.
func (m *Modifier) modifyUEIPInPDR(pdr *ie.IE, newUEIP net.IP) (*ie.IE, error) {
	// Get all child IEs from the Create/Update PDR
	childIEs := pdr.ChildIEs
	if len(childIEs) == 0 {
		return nil, nil
	}

	modified := false
	newChildren := make([]*ie.IE, 0, len(childIEs))

	for _, child := range childIEs {
		if child.Type == ie.PDI {
			// Found PDI - modify UE IP Address within it
			modifiedPDI, pdiModified := m.modifyUEIPInPDI(child, newUEIP)
			if pdiModified {
				newChildren = append(newChildren, modifiedPDI)
				modified = true
			} else {
				newChildren = append(newChildren, child)
			}
		} else {
			newChildren = append(newChildren, child)
		}
	}

	if !modified {
		return nil, nil
	}

	// Rebuild the Create/Update PDR IE with modified children
	newPDR := ie.NewCreatePDR(newChildren...)
	newPDR.Type = pdr.Type // Preserve original type (CreatePDR vs UpdatePDR)
	return newPDR, nil
}

// modifyUEIPInPDI modifies the UE IP Address IE within a PDI IE.
func (m *Modifier) modifyUEIPInPDI(pdi *ie.IE, newUEIP net.IP) (*ie.IE, bool) {
	childIEs := pdi.ChildIEs
	if len(childIEs) == 0 {
		return pdi, false
	}

	modified := false
	newChildren := make([]*ie.IE, 0, len(childIEs))

	for _, child := range childIEs {
		if child.Type == ie.UEIPAddress {
			newIE := m.createModifiedUEIPIE(child, newUEIP)
			if newIE != nil {
				newChildren = append(newChildren, newIE)
				modified = true
			} else {
				newChildren = append(newChildren, child)
			}
		} else {
			newChildren = append(newChildren, child)
		}
	}

	if !modified {
		return pdi, false
	}

	return ie.NewPDI(newChildren...), true
}

// createModifiedUEIPIE creates a new UE IP Address IE with the allocated IP.
func (m *Modifier) createModifiedUEIPIE(original *ie.IE, newUEIP net.IP) *ie.IE {
	ueIPFields, err := original.UEIPAddress()
	if err != nil {
		return nil
	}

	flags := ueIPFields.Flags

	if m.stripIPv6 {
		// Strip IPv6: clear V6 flag (bit 0 = 0x01), ensure V4 flag set (bit 1 = 0x02)
		flags = flags &^ 0x01 // clear V6
		flags = flags | 0x02  // set V4
		// Also clear IPv6D flag (bit 3 = 0x08) and IP6PL (bit 6 = 0x40)
		flags = flags &^ 0x08
		flags = flags &^ 0x40
		return ie.NewUEIPAddress(flags, newUEIP.String(), "", 0, 0)
	}

	// Preserve original flags, just replace IPv4
	if flags&0x02 != 0 { // V4 flag set
		v6str := ""
		var v6d, v6pl uint8
		if flags&0x01 != 0 && ueIPFields.IPv6Address != nil { // V6 flag set
			v6str = ueIPFields.IPv6Address.String()
			v6d = ueIPFields.IPv6PrefixDelegationBits
			v6pl = ueIPFields.IPv6PrefixLength
		}
		return ie.NewUEIPAddress(flags, newUEIP.String(), v6str, v6d, v6pl)
	}

	return nil
}

// ExtractCPSEID extracts the CP SEID from a Session Establishment Request's F-SEID IE.
func ExtractCPSEID(msg *message.SessionEstablishmentRequest) (uint64, error) {
	if msg.CPFSEID == nil {
		return 0, fmt.Errorf("no CP F-SEID in Session Establishment Request")
	}
	fseid, err := msg.CPFSEID.FSEID()
	if err != nil {
		return 0, fmt.Errorf("failed to parse CP F-SEID: %w", err)
	}
	return fseid.SEID, nil
}

// ExtractRemoteSEID extracts the UP SEID from a Session Establishment Response.
func ExtractRemoteSEID(msg *message.SessionEstablishmentResponse) (uint64, error) {
	if msg.UPFSEID == nil {
		return 0, fmt.Errorf("no UP F-SEID in Session Establishment Response")
	}
	fseid, err := msg.UPFSEID.FSEID()
	if err != nil {
		return 0, fmt.Errorf("failed to parse UP F-SEID: %w", err)
	}
	return fseid.SEID, nil
}

// ExtractHeaderSEID returns the SEID from the PFCP message header.
func ExtractHeaderSEID(msg message.Message) uint64 {
	return msg.SEID()
}

// ExtractCause extracts the Cause IE value from a response message.
func ExtractCause(ies []*ie.IE) (uint8, error) {
	for _, i := range ies {
		if i.Type == ie.Cause {
			cause, err := i.Cause()
			if err != nil {
				return 0, err
			}
			return cause, nil
		}
	}
	return 0, fmt.Errorf("no Cause IE found")
}
