package pfcp

import (
	"fmt"

	"github.com/wmnsk/go-pfcp/message"
)

// Decode parses raw bytes into a PFCP message.
func Decode(data []byte) (message.Message, error) {
	msg, err := message.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PFCP message: %w", err)
	}
	return msg, nil
}

// IsRequest returns true if the message type is a request (not a response).
func IsRequest(msg message.Message) bool {
	switch msg.MessageType() {
	case message.MsgTypeHeartbeatRequest,
		message.MsgTypeAssociationSetupRequest,
		message.MsgTypeAssociationUpdateRequest,
		message.MsgTypeAssociationReleaseRequest,
		message.MsgTypeSessionEstablishmentRequest,
		message.MsgTypeSessionModificationRequest,
		message.MsgTypeSessionDeletionRequest,
		message.MsgTypeSessionReportRequest:
		return true
	default:
		return false
	}
}

// IsSessionMessage returns true if the message is session-related (has SEID in header).
func IsSessionMessage(msg message.Message) bool {
	switch msg.MessageType() {
	case message.MsgTypeSessionEstablishmentRequest,
		message.MsgTypeSessionEstablishmentResponse,
		message.MsgTypeSessionModificationRequest,
		message.MsgTypeSessionModificationResponse,
		message.MsgTypeSessionDeletionRequest,
		message.MsgTypeSessionDeletionResponse,
		message.MsgTypeSessionReportRequest,
		message.MsgTypeSessionReportResponse:
		return true
	default:
		return false
	}
}

// MessageTypeName returns a human-readable name for a PFCP message type.
func MessageTypeName(msgType uint8) string {
	switch msgType {
	case message.MsgTypeHeartbeatRequest:
		return "HeartbeatRequest"
	case message.MsgTypeHeartbeatResponse:
		return "HeartbeatResponse"
	case message.MsgTypeAssociationSetupRequest:
		return "AssociationSetupRequest"
	case message.MsgTypeAssociationSetupResponse:
		return "AssociationSetupResponse"
	case message.MsgTypeAssociationUpdateRequest:
		return "AssociationUpdateRequest"
	case message.MsgTypeAssociationUpdateResponse:
		return "AssociationUpdateResponse"
	case message.MsgTypeAssociationReleaseRequest:
		return "AssociationReleaseRequest"
	case message.MsgTypeAssociationReleaseResponse:
		return "AssociationReleaseResponse"
	case message.MsgTypeSessionEstablishmentRequest:
		return "SessionEstablishmentRequest"
	case message.MsgTypeSessionEstablishmentResponse:
		return "SessionEstablishmentResponse"
	case message.MsgTypeSessionModificationRequest:
		return "SessionModificationRequest"
	case message.MsgTypeSessionModificationResponse:
		return "SessionModificationResponse"
	case message.MsgTypeSessionDeletionRequest:
		return "SessionDeletionRequest"
	case message.MsgTypeSessionDeletionResponse:
		return "SessionDeletionResponse"
	case message.MsgTypeSessionReportRequest:
		return "SessionReportRequest"
	case message.MsgTypeSessionReportResponse:
		return "SessionReportResponse"
	default:
		return fmt.Sprintf("Unknown(%d)", msgType)
	}
}
