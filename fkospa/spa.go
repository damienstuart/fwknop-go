package fkospa

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os/user"
	"time"
)

// Message represents an SPA (Single Packet Authorization) message.
type Message struct {
	RandVal        string
	Username       string
	Timestamp      time.Time
	MessageType    MessageType
	AccessMsg      string
	NATAccess      string // optional, required for NAT message types
	ServerAuth     string // optional
	ClientTimeout  uint32 // optional, required for timeout message types
	DigestType     DigestType
	EncryptionMode EncryptionMode
	HMACType       HMACType
}

// Option is a functional option for configuring a Message.
type Option func(*Message) error

// New creates a new Message with default values:
//   - Random 16-digit nonce
//   - Current timestamp
//   - Username from OS
//   - MessageType = AccessMsg
//   - DigestType = DigestSHA256
//   - EncryptionMode = EncryptionModeCBC
//   - HMACType = HMACSHA256
func New() (*Message, error) {
	return NewWithOptions()
}

// NewWithOptions creates a Message with defaults, then applies options.
func NewWithOptions(opts ...Option) (*Message, error) {
	randVal, err := generateRandVal()
	if err != nil {
		return nil, fmt.Errorf("generating random value: %w", err)
	}

	username, err := currentUsername()
	if err != nil {
		return nil, fmt.Errorf("detecting username: %w", err)
	}

	m := &Message{
		RandVal:        randVal,
		Username:       username,
		Timestamp:      time.Now(),
		MessageType:    AccessMsg,
		DigestType:     DigestSHA256,
		EncryptionMode: EncryptionModeCBC,
		HMACType:       HMACSHA256,
	}

	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// Functional options.

func WithRandVal(val string) Option {
	return func(m *Message) error {
		m.RandVal = val
		return nil
	}
}

func WithUsername(u string) Option {
	return func(m *Message) error {
		m.Username = u
		return nil
	}
}

func WithTimestamp(t time.Time) Option {
	return func(m *Message) error {
		m.Timestamp = t
		return nil
	}
}

func WithTimestampOffset(d time.Duration) Option {
	return func(m *Message) error {
		m.Timestamp = time.Now().Add(d)
		return nil
	}
}

func WithMessageType(mt MessageType) Option {
	return func(m *Message) error {
		if !mt.isValid() {
			return fmt.Errorf("%w: invalid message type %d", ErrInvalidData, mt)
		}
		m.MessageType = mt
		return nil
	}
}

func WithAccessMsg(msg string) Option {
	return func(m *Message) error {
		m.AccessMsg = msg
		return nil
	}
}

func WithNATAccess(nat string) Option {
	return func(m *Message) error {
		m.NATAccess = nat
		return nil
	}
}

func WithServerAuth(auth string) Option {
	return func(m *Message) error {
		m.ServerAuth = auth
		return nil
	}
}

func WithClientTimeout(seconds uint32) Option {
	return func(m *Message) error {
		m.ClientTimeout = seconds
		return nil
	}
}

func WithDigestType(dt DigestType) Option {
	return func(m *Message) error {
		if !dt.isValid() {
			return fmt.Errorf("%w: invalid digest type %d", ErrInvalidData, dt)
		}
		m.DigestType = dt
		return nil
	}
}

func WithEncryptionMode(mode EncryptionMode) Option {
	return func(m *Message) error {
		if !mode.isValid() {
			return fmt.Errorf("%w: invalid encryption mode %d", ErrInvalidData, mode)
		}
		m.EncryptionMode = mode
		return nil
	}
}

func WithHMACType(ht HMACType) Option {
	return func(m *Message) error {
		if !ht.isValid() {
			return fmt.Errorf("%w: invalid HMAC type %d", ErrInvalidData, ht)
		}
		m.HMACType = ht
		return nil
	}
}

// generateRandVal creates a 16-character decimal random value,
// matching the C implementation's FKO_RAND_VAL_SIZE behavior.
func generateRandVal() (string, error) {
	val := ""
	for len(val) < fkoRandValSize {
		n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
		if err != nil {
			return "", err
		}
		val += fmt.Sprintf("%d", n.Int64())
	}
	return val[:fkoRandValSize], nil
}

func currentUsername() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}
