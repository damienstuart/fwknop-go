package main

import (
	"fmt"
	"net"
)

// sendSPAPacket sends the SPA data string to the destination via UDP.
func sendSPAPacket(destination string, port int, spaData string) error {
	addr := net.JoinHostPort(destination, fmt.Sprintf("%d", port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	_, err = fmt.Fprint(conn, spaData)
	if err != nil {
		return fmt.Errorf("sending SPA packet to %s: %w", addr, err)
	}

	return nil
}
