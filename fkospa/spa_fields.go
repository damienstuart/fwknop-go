package fkospa

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const (
	maxSPAEncodedMsgSize = 1500
	minSPAEncodedMsgSize = 36
	maxSPAMessageSize    = 256
	maxSPAUsernameSize   = 64
	maxSPACmdLen         = 1400
	maxSPANATAccessSize  = 128
	maxPort              = 65535
	fkoRandValSize       = 16
	minSPAFields         = 6
	maxSPAFields         = 9
)

// validUsername checks that a username is non-empty, within size limits,
// and contains only printable non-space characters (matching the C
// validate_username logic).
func validUsername(username string) error {
	if username == "" {
		return fmt.Errorf("%w: username is empty", ErrMissingField)
	}
	if len(username) > maxSPAUsernameSize {
		return fmt.Errorf("%w: username too long", ErrInvalidData)
	}
	for _, r := range username {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%w: username contains invalid character", ErrInvalidData)
		}
	}
	return nil
}

// protoPortRe matches "tcp/22", "udp/53", etc.
var protoPortRe = regexp.MustCompile(`^(tcp|udp|icmp)/(\d+)$`)

// validAccessMsg validates an access message in the format "IP,proto/port"
// (e.g. "192.168.1.1,tcp/22").
func validAccessMsg(msg string) error {
	if msg == "" {
		return fmt.Errorf("%w: access message is empty", ErrMissingField)
	}
	if len(msg) > maxSPAMessageSize {
		return fmt.Errorf("%w: access message too long", ErrInvalidData)
	}

	parts := strings.SplitN(msg, ",", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: access message must be IP,proto/port", ErrInvalidData)
	}

	ip := parts[0]
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: invalid IP in access message: %s", ErrInvalidData, ip)
	}

	if !protoPortRe.MatchString(parts[1]) {
		return fmt.Errorf("%w: invalid proto/port: %s", ErrInvalidData, parts[1])
	}

	portStr := protoPortRe.FindStringSubmatch(parts[1])[2]
	port, _ := strconv.Atoi(portStr)
	if port < 1 || port > maxPort {
		return fmt.Errorf("%w: port out of range: %d", ErrInvalidData, port)
	}

	return nil
}

// validCmdMsg validates a command message.
func validCmdMsg(msg string) error {
	if msg == "" {
		return fmt.Errorf("%w: command message is empty", ErrMissingField)
	}
	if len(msg) > maxSPACmdLen {
		return fmt.Errorf("%w: command message too long", ErrInvalidData)
	}
	return nil
}

// validNATAccess validates a NAT access string.
func validNATAccess(nat string) error {
	if nat == "" {
		return fmt.Errorf("%w: NAT access is empty", ErrMissingField)
	}
	if len(nat) > maxSPANATAccessSize {
		return fmt.Errorf("%w: NAT access too long", ErrInvalidData)
	}
	return nil
}

// validRandVal checks that a random value is exactly fkoRandValSize
// decimal digits.
func validRandVal(val string) error {
	if len(val) != fkoRandValSize {
		return fmt.Errorf("%w: rand_val must be %d chars, got %d",
			ErrInvalidData, fkoRandValSize, len(val))
	}
	for _, c := range val {
		if c < '0' || c > '9' {
			return fmt.Errorf("%w: rand_val must be numeric", ErrInvalidData)
		}
	}
	return nil
}
