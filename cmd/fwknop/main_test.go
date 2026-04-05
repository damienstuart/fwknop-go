package main

import (
	"strings"
	"testing"
)

func TestRunKeyGen(t *testing.T) {
	err := runKeyGen()
	if err != nil {
		t.Fatalf("runKeyGen error: %v", err)
	}
}

func TestRunTestMode(t *testing.T) {
	// Run the client in test mode — builds the SPA packet but doesn't send.
	args := []string{
		"--destination", "127.0.0.1",
		"--access", "tcp/22",
		"--allow-ip", "10.0.0.1",
		"--key", "test_encryption_key",
		"--key-hmac", "test_hmac_key",
		"--test",
		"--no-rc-file",
	}

	err := run(args)
	if err != nil {
		t.Fatalf("run in test mode error: %v", err)
	}
}

func TestRunTestModeWithDigestTypes(t *testing.T) {
	digests := []string{"md5", "sha1", "sha256", "sha384", "sha512", "sha3-256", "sha3-512"}

	for _, d := range digests {
		t.Run(d, func(t *testing.T) {
			args := []string{
				"--destination", "127.0.0.1",
				"--access", "tcp/22",
				"--allow-ip", "10.0.0.1",
				"--key", "test_encryption_key",
				"--key-hmac", "test_hmac_key",
				"--digest-type", d,
				"--test",
				"--no-rc-file",
			}

			if err := run(args); err != nil {
				t.Fatalf("run with digest %s error: %v", d, err)
			}
		})
	}
}

func TestRunTestModeWithLegacyEncryption(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--access", "tcp/22",
		"--allow-ip", "10.0.0.1",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--encryption-mode", "legacy",
		"--test",
		"--no-rc-file",
	}

	if err := run(args); err != nil {
		t.Fatalf("run with legacy encryption error: %v", err)
	}
}

func TestRunTestModeWithTimeout(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--access", "tcp/22",
		"--allow-ip", "10.0.0.1",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--fw-timeout", "60",
		"--test",
		"--no-rc-file",
	}

	if err := run(args); err != nil {
		t.Fatalf("run with timeout error: %v", err)
	}
}

func TestRunTestModeWithNATAccess(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--access", "tcp/22",
		"--allow-ip", "10.0.0.1",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--nat-access", "192.168.1.100,22",
		"--test",
		"--no-rc-file",
	}

	if err := run(args); err != nil {
		t.Fatalf("run with NAT access error: %v", err)
	}
}

func TestRunTestModeWithServerCmd(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--server-cmd", "echo hello",
		"--allow-ip", "10.0.0.1",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--test",
		"--no-rc-file",
	}

	if err := run(args); err != nil {
		t.Fatalf("run with server command error: %v", err)
	}
}

func TestRunTestModeWithTimeOffset(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--access", "tcp/22",
		"--allow-ip", "10.0.0.1",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--time-offset-plus", "2m",
		"--test",
		"--no-rc-file",
	}

	if err := run(args); err != nil {
		t.Fatalf("run with time offset error: %v", err)
	}
}

func TestRunTestModeWithSpoofUser(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--access", "tcp/22",
		"--allow-ip", "10.0.0.1",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--spoof-user", "alice",
		"--test",
		"--no-rc-file",
	}

	if err := run(args); err != nil {
		t.Fatalf("run with spoof user error: %v", err)
	}
}

func TestRunMissingDestination(t *testing.T) {
	args := []string{
		"--access", "tcp/22",
		"--allow-ip", "10.0.0.1",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--no-rc-file",
	}

	err := run(args)
	if err == nil {
		t.Fatal("expected error for missing destination, got nil")
	}
	if !strings.Contains(err.Error(), "destination") {
		t.Errorf("expected error about destination, got: %v", err)
	}
}

func TestRunMissingAccess(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--allow-ip", "10.0.0.1",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--no-rc-file",
	}

	err := run(args)
	if err == nil {
		t.Fatal("expected error for missing access, got nil")
	}
	if !strings.Contains(err.Error(), "access") {
		t.Errorf("expected error about access, got: %v", err)
	}
}

func TestRunMissingKey(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--access", "tcp/22",
		"--allow-ip", "10.0.0.1",
		"--no-rc-file",
	}

	err := run(args)
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("expected error about key, got: %v", err)
	}
}

func TestRunMissingSourceIP(t *testing.T) {
	args := []string{
		"--destination", "127.0.0.1",
		"--access", "tcp/22",
		"--key", "test_key",
		"--key-hmac", "test_hmac",
		"--no-rc-file",
	}

	err := run(args)
	if err == nil {
		t.Fatal("expected error for missing source IP, got nil")
	}
	if !strings.Contains(err.Error(), "IP") {
		t.Errorf("expected error about IP, got: %v", err)
	}
}
