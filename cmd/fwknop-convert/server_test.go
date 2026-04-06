package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConvertServerBasic(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
VERBOSE         1;
MAX_SPA_PACKET_AGE    120;
SYSLOG_IDENTITY       fwknopd;
`)

	config, warnings, _ := parseServerConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if got := config["udp_port"]; got != "62201" {
		t.Errorf("udp_port = %v, want %q", got, "62201")
	}
	if got := config["verbose"]; got != "1" {
		t.Errorf("verbose = %v, want %q", got, "1")
	}
	if got := config["max_spa_packet_age"]; got != "120" {
		t.Errorf("max_spa_packet_age = %v, want %q", got, "120")
	}
	if got := config["syslog_identity"]; got != "fwknopd" {
		t.Errorf("syslog_identity = %v, want %q", got, "fwknopd")
	}
}

func TestConvertServerSemicolonStripping(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
VERBOSE         1;
`)

	config, _, _ := parseServerConfig(data)

	if got := config["udp_port"]; got != "62201" {
		t.Errorf("udp_port = %v (semicolon not stripped?)", got)
	}
}

func TestConvertServerPcapKeysIgnored(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
PCAP_INTF       eth0;
PCAP_FILTER     udp port 62201;
ENABLE_PCAP_PROMISC    N;
MAX_SNIFF_BYTES        1500;
PCAP_DISPATCH_COUNT    100;
PCAP_LOOP_SLEEP        100000;
`)

	config, warnings, _ := parseServerConfig(data)

	// pcap keys should be silently ignored, not warned.
	if len(warnings) != 0 {
		t.Errorf("pcap keys should be silently ignored, got warnings: %v", warnings)
	}
	if got := config["udp_port"]; got != "62201" {
		t.Errorf("udp_port = %v", got)
	}
}

func TestConvertServerIPTDetection(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
IPT_INPUT_ACCESS    ACCEPT, filter, INPUT, 1, FWKNOP_INPUT, 1;
FLUSH_IPT_AT_INIT   Y;
FLUSH_IPT_AT_EXIT   Y;
ENABLE_IPT_FORWARDING    N;
`)

	config, warnings, fwBackend := parseServerConfig(data)

	if fwBackend != "iptables" {
		t.Errorf("firewall backend = %q, want %q", fwBackend, "iptables")
	}
	// No warnings expected for iptables keys.
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if got := config["udp_port"]; got != "62201" {
		t.Errorf("udp_port = %v", got)
	}
}

func TestConvertServerFirewalldDetection(t *testing.T) {
	data := []byte(`FIREWD_INPUT_ACCESS    ACCEPT, filter, INPUT, 1, FWKNOP_INPUT, 1;
FLUSH_FIREWD_AT_INIT   Y;
`)

	_, _, fwBackend := parseServerConfig(data)

	if fwBackend != "firewalld" {
		t.Errorf("firewall backend = %q, want %q", fwBackend, "firewalld")
	}
}

func TestConvertServerIPFWDetection(t *testing.T) {
	data := []byte(`IPFW_START_RULE_NUM    10000;
FLUSH_IPFW_AT_INIT     Y;
`)

	_, _, fwBackend := parseServerConfig(data)

	if fwBackend != "ipfw" {
		t.Errorf("firewall backend = %q, want %q", fwBackend, "ipfw")
	}
}

func TestConvertServerPFDetection(t *testing.T) {
	data := []byte(`PF_ANCHOR_NAME    fwknop;
PF_EXPIRE_INTERVAL    30;
`)

	_, _, fwBackend := parseServerConfig(data)

	if fwBackend != "pf" {
		t.Errorf("firewall backend = %q, want %q", fwBackend, "pf")
	}
}

func TestConvertServerGPGWarnings(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
GPG_HOME_DIR    /root/.gnupg;
GPG_EXE         /usr/bin/gpg;
`)

	_, warnings, _ := parseServerConfig(data)

	if len(warnings) != 2 {
		t.Errorf("expected 2 GPG warnings, got %d: %v", len(warnings), warnings)
	}
	for _, w := range warnings {
		if !strings.Contains(w, "GPG") {
			t.Errorf("expected GPG-related warning, got: %s", w)
		}
	}
}

func TestConvertServerHTTPWarnings(t *testing.T) {
	data := []byte(`ENABLE_SPA_OVER_HTTP    Y;
ALLOW_ANY_USER_AGENT    N;
ENABLE_X_FORWARDED_FOR  N;
`)

	_, warnings, _ := parseServerConfig(data)

	if len(warnings) != 3 {
		t.Errorf("expected 3 HTTP warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestConvertServerExternalCmdWarnings(t *testing.T) {
	data := []byte(`ENABLE_EXTERNAL_CMDS    Y;
EXTERNAL_CMD_OPEN       /usr/bin/my_open;
EXTERNAL_CMD_CLOSE      /usr/bin/my_close;
EXTERNAL_CMD_ALARM      30;
`)

	_, warnings, _ := parseServerConfig(data)

	if len(warnings) != 4 {
		t.Errorf("expected 4 external cmd warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestConvertServerBooleans(t *testing.T) {
	data := []byte(`ENABLE_SPA_PACKET_AGING    Y;
ENABLE_DIGEST_PERSISTENCE  N;
`)

	config, _, _ := parseServerConfig(data)

	if got := config["enable_spa_packet_aging"]; got != true {
		t.Errorf("enable_spa_packet_aging = %v, want true", got)
	}
	if got := config["enable_digest_persistence"]; got != false {
		t.Errorf("enable_digest_persistence = %v, want false", got)
	}
}

func TestConvertServerComments(t *testing.T) {
	data := []byte(`# This is a comment
UDPSERV_PORT    62201;
# Another comment
VERBOSE         1;
`)

	config, _, _ := parseServerConfig(data)

	if got := config["udp_port"]; got != "62201" {
		t.Errorf("udp_port = %v", got)
	}
}

func TestConvertServerAllValidKeys(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
VERBOSE         2;
MAX_SPA_PACKET_AGE    120;
SYSLOG_IDENTITY       fwknopd;
SYSLOG_FACILITY       LOG_DAEMON;
FWKNOP_RUN_DIR        /var/run/fwknop;
FWKNOP_PID_FILE       /var/run/fwknop/fwknopd.pid;
ACCESS_FILE           /etc/fwknop/access.conf;
ENABLE_SPA_PACKET_AGING    Y;
ENABLE_DIGEST_PERSISTENCE  Y;
`)

	config, warnings, _ := parseServerConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(config) != 10 {
		t.Errorf("expected 10 config entries, got %d: %v", len(config), config)
	}
}

func TestConvertServerActionTemplateInOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fwknopd.conf")
	os.WriteFile(path, []byte(`UDPSERV_PORT    62201;
IPT_INPUT_ACCESS    ACCEPT, filter, INPUT, 1, FWKNOP_INPUT, 1;
`), 0600)

	err := convertServer(path)
	if err != nil {
		t.Fatalf("convertServer error: %v", err)
	}
}

func TestConvertServerEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fwknopd.conf")
	os.WriteFile(path, []byte(`UDPSERV_PORT    62201;
VERBOSE         1;
`), 0600)

	err := convertServer(path)
	if err != nil {
		t.Fatalf("convertServer error: %v", err)
	}
}

func TestConvertServerMissingFile(t *testing.T) {
	err := convertServer("/nonexistent/fwknopd.conf")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
