// Command fwknop is the Go implementation of the fwknop SPA client.
// It creates and sends Single Packet Authorization requests to an
// fwknop server to request access to services behind a firewall.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fwknop: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := loadConfig(args)
	if err != nil {
		return err
	}

	// Handle informational commands that exit early.
	if cfg.ShowVersion {
		fmt.Printf("fwknop (Go) version %s (SPA protocol %s)\n", version, fkospa.ProtocolVersion)
		return nil
	}

	if cfg.KeyGen {
		return runKeyGen()
	}

	if cfg.ConvertRC != "" {
		yamlData, err := convertLegacyRC(cfg.ConvertRC)
		if err != nil {
			return fmt.Errorf("converting rc file: %w", err)
		}
		fmt.Print(string(yamlData))
		return nil
	}

	if cfg.ListStanzas {
		rcPath := cfg.RCFile
		if rcPath == "" {
			home, _ := os.UserHomeDir()
			rcPath = filepath.Join(home, ".fwknoprc")
		}
		return listStanzas(rcPath)
	}

	// Validate required fields.
	if cfg.Destination == "" {
		return fmt.Errorf("destination is required (use -D/--destination)")
	}
	if cfg.Access == "" && cfg.ServerCmd == "" {
		return fmt.Errorf("access specification is required (use -A/--access)")
	}

	// Resolve the allow IP.
	allowIP := cfg.AllowIP
	if cfg.SourceIP {
		allowIP = "0.0.0.0"
	}
	if cfg.ResolveIP && allowIP == "" {
		url := cfg.ResolveURL
		if url == "" {
			url = defaultResolveURL
		}
		if cfg.Verbose > 0 {
			fmt.Fprintf(os.Stderr, "Resolving external IP via %s...\n", url)
		}
		resolved, err := resolveExternalIP(url)
		if err != nil {
			return err
		}
		allowIP = resolved
		if cfg.Verbose > 0 {
			fmt.Fprintf(os.Stderr, "Resolved external IP: %s\n", allowIP)
		}
	}
	if allowIP == "" {
		return fmt.Errorf("no source IP specified (use -a, -s, or -R)")
	}

	// Resolve crypto settings.
	encKey, err := cfg.resolveEncKey()
	if err != nil {
		return err
	}
	hmacKey, err := cfg.resolveHMACKey()
	if err != nil {
		return err
	}

	digestType, err := resolveDigestType(cfg.DigestType)
	if err != nil {
		return err
	}

	encMode, err := resolveEncMode(cfg.EncryptionMode)
	if err != nil {
		return err
	}

	// Build SPA message options.
	opts := []fkospa.Option{
		fkospa.WithDigestType(digestType),
		fkospa.WithEncryptionMode(encMode),
	}

	if cfg.UseHMAC {
		hmacType, err := resolveHMACType(cfg.HMACDigestType)
		if err != nil {
			return err
		}
		opts = append(opts, fkospa.WithHMACType(hmacType))
	}

	if cfg.SpoofUser != "" {
		opts = append(opts, fkospa.WithUsername(cfg.SpoofUser))
	}

	if cfg.FWTimeout > 0 {
		opts = append(opts, fkospa.WithClientTimeout(uint32(cfg.FWTimeout)))
	}

	// Handle time offsets.
	if cfg.TimeOffsetPlus != "" {
		d, err := parseTimeOffset(cfg.TimeOffsetPlus)
		if err != nil {
			return err
		}
		opts = append(opts, fkospa.WithTimestampOffset(d))
	} else if cfg.TimeOffsetMinus != "" {
		d, err := parseTimeOffset(cfg.TimeOffsetMinus)
		if err != nil {
			return err
		}
		opts = append(opts, fkospa.WithTimestampOffset(-d))
	}

	// Determine message type and access message.
	if cfg.ServerCmd != "" {
		opts = append(opts, fkospa.WithMessageType(fkospa.CommandMsg))
		opts = append(opts, fkospa.WithAccessMsg(cfg.ServerCmd))
	} else {
		accessMsg := fmt.Sprintf("%s,%s", allowIP, cfg.Access)
		opts = append(opts, fkospa.WithAccessMsg(accessMsg))
	}

	// NAT options.
	if cfg.NATAccess != "" {
		if cfg.NATLocal {
			opts = append(opts, fkospa.WithMessageType(fkospa.LocalNATAccessMsg))
		} else {
			opts = append(opts, fkospa.WithMessageType(fkospa.NATAccessMsg))
		}
		opts = append(opts, fkospa.WithNATAccess(cfg.NATAccess))
	}

	// Create the SPA message.
	msg, err := fkospa.NewWithOptions(opts...)
	if err != nil {
		return fmt.Errorf("creating SPA message: %w", err)
	}

	if cfg.Verbose > 0 {
		printSPADetails(msg)
	}

	// Encrypt.
	spaData, err := msg.Encrypt(encKey, hmacKey)
	if err != nil {
		return fmt.Errorf("encrypting SPA data: %w", err)
	}

	if cfg.Verbose > 0 {
		fmt.Fprintf(os.Stderr, "SPA data length: %d bytes\n", len(spaData))
	}
	if cfg.Verbose > 1 {
		fmt.Fprintf(os.Stderr, "SPA data: %s\n", spaData)
	}

	// Test mode: print but don't send.
	if cfg.Test {
		fmt.Println(spaData)
		return nil
	}

	// Send.
	if cfg.Verbose > 0 {
		fmt.Fprintf(os.Stderr, "Sending SPA packet to %s:%d (UDP)...\n",
			cfg.Destination, cfg.ServerPort)
	}

	if err := sendSPAPacket(cfg.Destination, cfg.ServerPort, spaData); err != nil {
		return err
	}

	if cfg.Verbose > 0 {
		fmt.Fprintln(os.Stderr, "SPA packet sent successfully.")
	}

	return nil
}

func runKeyGen() error {
	encKey, err := fkospa.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("generating encryption key: %w", err)
	}
	hmacKey, err := fkospa.GenerateHMACKey(32)
	if err != nil {
		return fmt.Errorf("generating HMAC key: %w", err)
	}

	fmt.Printf("KEY_BASE64: %s\n", encKey)
	fmt.Printf("HMAC_KEY_BASE64: %s\n", hmacKey)

	return nil
}

func printSPADetails(m *fkospa.Message) {
	fmt.Fprintln(os.Stderr, "SPA message details:")
	fmt.Fprintf(os.Stderr, "  Random value: %s\n", m.RandVal)
	fmt.Fprintf(os.Stderr, "  Username:     %s\n", m.Username)
	fmt.Fprintf(os.Stderr, "  Timestamp:    %s (%d)\n",
		m.Timestamp.Format(time.RFC3339), m.Timestamp.Unix())
	fmt.Fprintf(os.Stderr, "  Message type: %s\n", m.MessageType)
	fmt.Fprintf(os.Stderr, "  Access:       %s\n", m.AccessMsg)
	if m.NATAccess != "" {
		fmt.Fprintf(os.Stderr, "  NAT access:   %s\n", m.NATAccess)
	}
	if m.ServerAuth != "" {
		fmt.Fprintf(os.Stderr, "  Server auth:  %s\n", m.ServerAuth)
	}
	if m.ClientTimeout > 0 {
		fmt.Fprintf(os.Stderr, "  Timeout:      %ds\n", m.ClientTimeout)
	}
	fmt.Fprintf(os.Stderr, "  Digest:       %s\n", m.DigestType)
	fmt.Fprintf(os.Stderr, "  Encryption:   %s\n", m.EncryptionMode)
	fmt.Fprintf(os.Stderr, "  HMAC:         %s\n", m.HMACType)
}

