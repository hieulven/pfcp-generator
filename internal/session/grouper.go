package session

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"

	"pfcp-generator/internal/pfcp"
	"pfcp-generator/pkg/types"
)

// PreEncodedTemplate holds pre-encoded PFCP messages for stress mode hot path.
// Instead of decode→modify→encode per session, workers copy the pre-encoded bytes
// and patch only the per-session variable fields (SEID, UE IP, seq num) in-place.
type PreEncodedTemplate struct {
	EstMsg  *pfcp.PreEncodedMsg   // pre-encoded Session Establishment Request
	ModMsgs []*pfcp.PreEncodedMsg // pre-encoded Session Modification Requests (no deletions)
}

// BuildPreEncodedTemplates pre-encodes each SessionTemplate's messages using modifier.
// Templates that fail to pre-encode are silently dropped (caller should check len).
func BuildPreEncodedTemplates(templates []SessionTemplate, modifier *pfcp.Modifier) []PreEncodedTemplate {
	result := make([]PreEncodedTemplate, 0, len(templates))
	for i := range templates {
		tmpl := &templates[i]
		if len(tmpl.Messages) == 0 {
			continue
		}

		// Pre-encode establishment (first message)
		estPre, err := pfcp.PreEncodeEstablishment(modifier, tmpl.Messages[0].Data)
		if err != nil {
			log.WithError(err).WithField("template", i).Warn("Failed to pre-encode establishment, skipping template")
			continue
		}

		// Pre-encode modification messages (skip establishment and deletion)
		var modPres []*pfcp.PreEncodedMsg
		for j := 1; j < len(tmpl.Messages); j++ {
			raw := tmpl.Messages[j]
			if len(raw.Data) > 1 && raw.Data[1] == message.MsgTypeSessionDeletionRequest {
				continue
			}
			modPre, err := pfcp.PreEncodeModification(modifier, raw.Data)
			if err != nil {
				log.WithError(err).WithField("template", i).WithField("msg", j).Debug("Failed to pre-encode modification, skipping")
				continue
			}
			modPres = append(modPres, modPre)
		}

		result = append(result, PreEncodedTemplate{
			EstMsg:  estPre,
			ModMsgs: modPres,
		})
	}
	return result
}

// SessionTemplate represents a complete session lifecycle extracted from a pcap:
// Association (optional) + Establishment + N×Modification + Deletion (optional).
type SessionTemplate struct {
	// AssociationSetup is sent once before the first session, not per-session.
	AssociationSetup *types.RawPFCPMessage

	// Heartbeats are sent outside session context.
	Heartbeats []types.RawPFCPMessage

	// Messages is the ordered list of session-level messages
	// (Establishment, Modifications, Deletion) for one session lifecycle.
	Messages []types.RawPFCPMessage

	// OriginalCPSEID is the CP SEID from the pcap's Establishment Request.
	OriginalCPSEID uint64

	// OriginalRemoteSEID from the pcap's Establishment Response (if available).
	OriginalRemoteSEID uint64

	// HasDeletion indicates whether the template includes a Session Deletion.
	HasDeletion bool
}

// ReplayPlan contains the parsed session templates and global messages.
type ReplayPlan struct {
	// AssociationSetup to send once at startup (nil if not present).
	AssociationSetup *types.RawPFCPMessage

	// Heartbeats to send periodically (outside session context).
	Heartbeats []types.RawPFCPMessage

	// Templates are the per-session message sequences.
	Templates []SessionTemplate

	// SEIDMappings from pcap responses.
	SEIDMappings []types.SEIDMapping

	// MessagesPerSession is the number of messages in a typical session template.
	MessagesPerSession int
}

// BuildReplayPlan groups pcap messages into session templates.
// It uses the original CP SEID to correlate Establishment, Modification, and Deletion messages.
func BuildReplayPlan(messages []types.RawPFCPMessage, seidMappings []types.SEIDMapping) (*ReplayPlan, error) {
	plan := &ReplayPlan{
		SEIDMappings: seidMappings,
	}

	// Build reverse mapping: original remote SEID → original CP SEID
	remoteToCPSEID := make(map[uint64]uint64)
	for _, m := range seidMappings {
		remoteToCPSEID[m.OriginalRemoteSEID] = m.OriginalCPSEID
	}

	// Map from original CP SEID to template index
	cpSEIDToIdx := make(map[uint64]int)

	for _, raw := range messages {
		msg, err := pfcp.Decode(raw.Data)
		if err != nil {
			log.WithError(err).Warn("Skipping unparseable message in grouper")
			continue
		}

		switch msg.MessageType() {
		case message.MsgTypeAssociationSetupRequest:
			r := raw // copy
			plan.AssociationSetup = &r

		case message.MsgTypeHeartbeatRequest:
			plan.Heartbeats = append(plan.Heartbeats, raw)

		case message.MsgTypeSessionEstablishmentRequest:
			cpSEID, err := pfcp.ExtractCPSEID(msg.(*message.SessionEstablishmentRequest))
			if err != nil {
				log.WithError(err).Warn("Could not extract CP SEID from Establishment, skipping")
				continue
			}

			idx := len(plan.Templates)
			tmpl := SessionTemplate{
				OriginalCPSEID: cpSEID,
				Messages:       []types.RawPFCPMessage{raw},
			}
			// Check if we have a remote SEID mapping
			for _, m := range seidMappings {
				if m.OriginalCPSEID == cpSEID {
					tmpl.OriginalRemoteSEID = m.OriginalRemoteSEID
					break
				}
			}
			plan.Templates = append(plan.Templates, tmpl)
			cpSEIDToIdx[cpSEID] = idx

		case message.MsgTypeSessionModificationRequest, message.MsgTypeSessionDeletionRequest:
			// Header SEID is the original remote SEID (UPF's SEID)
			headerSEID := pfcp.ExtractHeaderSEID(msg)

			// Try to find which session this belongs to
			cpSEID, found := remoteToCPSEID[headerSEID]
			if !found {
				// Fallback: header SEID might be the CP SEID itself
				if _, ok := cpSEIDToIdx[headerSEID]; ok {
					cpSEID = headerSEID
					found = true
				}
			}

			if !found {
				log.WithField("header_seid", headerSEID).Warn("Cannot correlate message to session, skipping")
				continue
			}

			idx, ok := cpSEIDToIdx[cpSEID]
			if !ok {
				log.WithField("cp_seid", cpSEID).Warn("Session template not found, skipping")
				continue
			}

			plan.Templates[idx].Messages = append(plan.Templates[idx].Messages, raw)
			if msg.MessageType() == message.MsgTypeSessionDeletionRequest {
				plan.Templates[idx].HasDeletion = true
			}

		default:
			log.WithField("msg_type", pfcp.MessageTypeName(msg.MessageType())).Debug("Skipping unsupported message type in grouper")
		}
	}

	if len(plan.Templates) == 0 {
		return nil, fmt.Errorf("no session templates found in pcap")
	}

	// Calculate average messages per session
	totalMsgs := 0
	for _, t := range plan.Templates {
		totalMsgs += len(t.Messages)
	}
	plan.MessagesPerSession = totalMsgs / len(plan.Templates)
	if plan.MessagesPerSession < 1 {
		plan.MessagesPerSession = 1
	}

	log.WithFields(log.Fields{
		"templates":            len(plan.Templates),
		"messages_per_session": plan.MessagesPerSession,
		"has_association":      plan.AssociationSetup != nil,
		"heartbeats":           len(plan.Heartbeats),
	}).Info("Built replay plan")

	return plan, nil
}
