package fkospa

import "fmt"

// MessageType identifies the type of SPA message.
type MessageType int

const (
	CommandMsg                       MessageType = 0
	AccessMsg                        MessageType = 1
	NATAccessMsg                     MessageType = 2
	ClientTimeoutAccessMsg           MessageType = 3
	ClientTimeoutNATAccessMsg        MessageType = 4
	LocalNATAccessMsg                MessageType = 5
	ClientTimeoutLocalNATAccessMsg   MessageType = 6
)

// String returns a human-readable name for the message type.
func (mt MessageType) String() string {
	switch mt {
	case CommandMsg:
		return "Command"
	case AccessMsg:
		return "Access"
	case NATAccessMsg:
		return "NATAccess"
	case ClientTimeoutAccessMsg:
		return "ClientTimeoutAccess"
	case ClientTimeoutNATAccessMsg:
		return "ClientTimeoutNATAccess"
	case LocalNATAccessMsg:
		return "LocalNATAccess"
	case ClientTimeoutLocalNATAccessMsg:
		return "ClientTimeoutLocalNATAccess"
	default:
		return fmt.Sprintf("Unknown(%d)", int(mt))
	}
}

func (mt MessageType) isValid() bool {
	return mt >= CommandMsg && mt <= ClientTimeoutLocalNATAccessMsg
}

func (mt MessageType) requiresNATAccess() bool {
	switch mt {
	case NATAccessMsg, ClientTimeoutNATAccessMsg,
		LocalNATAccessMsg, ClientTimeoutLocalNATAccessMsg:
		return true
	default:
		return false
	}
}

func (mt MessageType) requiresClientTimeout() bool {
	switch mt {
	case ClientTimeoutAccessMsg, ClientTimeoutNATAccessMsg,
		ClientTimeoutLocalNATAccessMsg:
		return true
	default:
		return false
	}
}
