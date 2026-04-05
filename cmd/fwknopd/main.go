// Command fwknopd is the Go implementation of the fwknop SPA server.
// It listens for incoming Single Packet Authorization requests via UDP,
// decrypts and validates them, and logs the results.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fwknopd: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := loadServerConfig(args)
	if err != nil {
		return err
	}

	if cfg.ShowVersion {
		fmt.Printf("fwknopd (Go) version %s (SPA protocol %s)\n", serverVersion, fkospa.ProtocolVersion)
		return nil
	}

	if cfg.Status {
		return showStatus(cfg.PIDFile)
	}

	if cfg.Kill {
		return signalDaemon(cfg.PIDFile, syscall.SIGTERM)
	}

	if cfg.Restart {
		return signalDaemon(cfg.PIDFile, syscall.SIGHUP)
	}

	// Load access configuration.
	stanzas, err := loadAccessConfig(cfg.AccessFile)
	if err != nil {
		return err
	}

	if cfg.DumpConfig {
		dumpConfig(cfg, stanzas)
		return nil
	}

	// Set up logging.
	logger, err := newSPALogger(cfg.LogFile, cfg.SyslogIdent, cfg.SyslogFacility, cfg.Verbose, cfg.Foreground)
	if err != nil {
		return err
	}
	defer logger.Close()

	logger.Info("Starting fwknopd (Go) version %s", serverVersion)
	logger.Info("Loaded %d access stanza(s) from %s", len(stanzas), cfg.AccessFile)

	// Set up replay cache with TTL matching max SPA packet age.
	replayTTL := time.Duration(cfg.MaxSPAPacketAge) * time.Second
	replay := newReplayCache(replayTTL)
	logger.Info("Replay cache initialized (TTL: %s)", replayTTL)

	// Set up actions manager.
	am, err := newActionsManager(cfg.Actions, logger)
	if err != nil {
		return fmt.Errorf("actions config: %w", err)
	}

	if err := am.Validate(); err != nil {
		return err
	}
	if err := am.Init(); err != nil {
		return err
	}

	// Write PID file.
	if !cfg.Foreground {
		if err := writePIDFile(cfg.PIDFile); err != nil {
			logger.Warn("Failed to write PID file: %v", err)
		} else {
			logger.Info("PID file written: %s", cfg.PIDFile)
		}
		defer os.Remove(cfg.PIDFile)
	}

	// Handle signals for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigCh
		logger.Info("Received signal %v, shutting down...", sig)
		am.Shutdown()
		os.Exit(0)
	}()

	if cfg.Test {
		logger.Info("Running in test mode — no actions will be taken.")
	}

	// Start the UDP server (blocks).
	return udpServer(cfg, stanzas, replay, logger, am)
}

// writePIDFile writes the current process PID to the specified file.
func writePIDFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
}

// showStatus reads the PID file and checks if the process is running.
func showStatus(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Println("fwknopd does not appear to be running (no PID file).")
		return nil
	}

	pid, err := strconv.Atoi(string(data[:len(data)-1]))
	if err != nil {
		return fmt.Errorf("invalid PID file content: %s", pidFile)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Printf("fwknopd PID %d (from %s) — process not found.\n", pid, pidFile)
		return nil
	}

	// On Unix, FindProcess always succeeds. Send signal 0 to check if alive.
	if err := process.Signal(syscall.Signal(0)); err != nil {
		fmt.Printf("fwknopd PID %d (from %s) — not running.\n", pid, pidFile)
	} else {
		fmt.Printf("fwknopd is running (PID %d).\n", pid)
	}
	return nil
}

// signalDaemon sends a signal to the running fwknopd process.
func signalDaemon(pidFile string, sig syscall.Signal) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("cannot read PID file %s: %w", pidFile, err)
	}

	pid, err := strconv.Atoi(string(data[:len(data)-1]))
	if err != nil {
		return fmt.Errorf("invalid PID in %s", pidFile)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("process %d not found", pid)
	}

	if err := process.Signal(sig); err != nil {
		return fmt.Errorf("sending signal to PID %d: %w", pid, err)
	}

	fmt.Printf("Sent signal %v to fwknopd (PID %d).\n", sig, pid)
	return nil
}

// dumpConfig prints the current configuration and access stanzas.
func dumpConfig(cfg *serverConfig, stanzas []accessStanza) {
	fmt.Println("fwknopd configuration:")
	fmt.Printf("  Config file:    %s\n", cfg.ConfigFile)
	fmt.Printf("  Access file:    %s\n", cfg.AccessFile)
	fmt.Printf("  UDP port:       %d\n", cfg.UDPPort)
	fmt.Printf("  Bind address:   %s\n", cfg.BindAddress)
	fmt.Printf("  Log file:       %s\n", cfg.LogFile)
	fmt.Printf("  Syslog ident:   %s\n", cfg.SyslogIdent)
	fmt.Printf("  PID file:       %s\n", cfg.PIDFile)
	fmt.Printf("  Max packet age: %ds\n", cfg.MaxSPAPacketAge)
	fmt.Printf("  Verbose:        %v\n", cfg.Verbose)
	fmt.Printf("  Test mode:      %v\n", cfg.Test)
	fmt.Println()

	fmt.Printf("Access stanzas (%d):\n", len(stanzas))
	for i, s := range stanzas {
		fmt.Printf("  Stanza #%d:\n", i+1)
		fmt.Printf("    Source:           %s\n", s.Source)
		fmt.Printf("    Open ports:       %v\n", s.OpenPorts)
		fmt.Printf("    HMAC digest:      %s\n", s.HMACDigestType)
		fmt.Printf("    Encryption mode:  %s\n", s.EncryptionMode)
		fmt.Printf("    Access timeout:   %ds\n", s.AccessTimeout)
		fmt.Printf("    Require username: %s\n", s.RequireUsername)
		fmt.Printf("    Require src addr: %v\n", s.RequireSourceAddr)
		fmt.Printf("    Enc key length:   %d bytes\n", len(s.encKey))
		fmt.Printf("    HMAC key length:  %d bytes\n", len(s.hmacKey))
	}
}
