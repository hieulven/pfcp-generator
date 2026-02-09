package pfcp

import (
	"fmt"

	"github.com/wmnsk/go-pfcp/message"
)

// Encode serializes a PFCP message to bytes.
func Encode(msg message.Message) ([]byte, error) {
	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		return nil, fmt.Errorf("failed to marshal PFCP message: %w", err)
	}
	return b, nil
}
