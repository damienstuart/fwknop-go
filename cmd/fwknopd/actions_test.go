package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func testActionLogger() *spaLogger {
	return &spaLogger{
		fileLogger: nil, // suppress output in tests
		verbose:    true,
	}
}

func TestNewActionsManagerParsesTemplates(t *testing.T) {
	cfg := actionsConfig{
		Check: "iptables -C INPUT -s {{.SourceIP}} -j ACCEPT",
		Open:  "iptables -A INPUT -s {{.SourceIP}} -j ACCEPT",
		Close: "iptables -D INPUT -s {{.SourceIP}} -j ACCEPT",
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}
	if fm.checkTmpl == nil {
		t.Error("check template should be parsed")
	}
	if fm.openTmpl == nil {
		t.Error("open template should be parsed")
	}
	if fm.closeTmpl == nil {
		t.Error("close template should be parsed")
	}
}

func TestNewActionsManagerInvalidTemplate(t *testing.T) {
	cfg := actionsConfig{
		Open: "{{.Invalid",
	}
	_, err := newActionsManager(cfg, testActionLogger())
	if err == nil {
		t.Error("expected error for invalid template, got nil")
	}
}

func TestNewActionsManagerEmptyConfig(t *testing.T) {
	fm, err := newActionsManager(actionsConfig{}, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}
	if fm.checkTmpl != nil || fm.openTmpl != nil || fm.closeTmpl != nil {
		t.Error("empty config should produce nil templates")
	}
}

func TestValidateSuccess(t *testing.T) {
	cfg := actionsConfig{Validate: "true"}
	fm, _ := newActionsManager(cfg, testActionLogger())
	if err := fm.Validate(); err != nil {
		t.Errorf("Validate error: %v", err)
	}
}

func TestValidateFailure(t *testing.T) {
	cfg := actionsConfig{Validate: "false"}
	fm, _ := newActionsManager(cfg, testActionLogger())
	if err := fm.Validate(); err == nil {
		t.Error("expected Validate to fail")
	}
}

func TestValidateEmpty(t *testing.T) {
	fm, _ := newActionsManager(actionsConfig{}, testActionLogger())
	if err := fm.Validate(); err != nil {
		t.Errorf("empty Validate should succeed: %v", err)
	}
}

func TestInitSuccess(t *testing.T) {
	cfg := actionsConfig{Init: "true"}
	fm, _ := newActionsManager(cfg, testActionLogger())
	if err := fm.Init(); err != nil {
		t.Errorf("Init error: %v", err)
	}
}

func TestOpenRuleWithEchoCommands(t *testing.T) {
	dir := t.TempDir()
	openLog := filepath.Join(dir, "open.log")

	cfg := actionsConfig{
		Open:  "echo {{.SourceIP}} {{.Proto}} {{.Port}} >> " + openLog,
		Close: "echo close {{.SourceIP}} >> " + filepath.Join(dir, "close.log"),
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	ctx := templateContext{
		SourceIP: "10.0.0.1",
		Proto:    "tcp",
		Port:     "22",
		Timeout:  1,
	}

	if err := fm.OpenRule(ctx); err != nil {
		t.Fatalf("OpenRule error: %v", err)
	}

	// Verify open command was executed.
	data, err := os.ReadFile(openLog)
	if err != nil {
		t.Fatalf("reading open log: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "10.0.0.1 tcp 22" {
		t.Errorf("open log = %q, want %q", got, "10.0.0.1 tcp 22")
	}

	if fm.ActiveRuleCount() != 1 {
		t.Errorf("active rules = %d, want 1", fm.ActiveRuleCount())
	}

	// Wait for close timer.
	time.Sleep(1500 * time.Millisecond)

	if fm.ActiveRuleCount() != 0 {
		t.Errorf("active rules after timeout = %d, want 0", fm.ActiveRuleCount())
	}
}

func TestCheckSkipsOpen(t *testing.T) {
	dir := t.TempDir()
	openLog := filepath.Join(dir, "open.log")

	cfg := actionsConfig{
		Check: "true", // exit 0 → rule exists
		Open:  "echo opened >> " + openLog,
		Close: "true",
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	ctx := templateContext{
		SourceIP: "10.0.0.1",
		Proto:    "tcp",
		Port:     "22",
		Timeout:  30,
	}

	if err := fm.OpenRule(ctx); err != nil {
		t.Fatalf("OpenRule error: %v", err)
	}

	// Open command should NOT have been executed since check returned 0.
	if _, err := os.Stat(openLog); err == nil {
		t.Error("open command should not have been executed when check succeeds")
	}

	fm.Shutdown()
}

func TestCheckFailsProceeds(t *testing.T) {
	dir := t.TempDir()
	openLog := filepath.Join(dir, "open.log")

	cfg := actionsConfig{
		Check: "false", // exit 1 → rule doesn't exist
		Open:  "echo opened >> " + openLog,
		Close: "true",
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	ctx := templateContext{
		SourceIP: "10.0.0.1",
		Proto:    "tcp",
		Port:     "22",
		Timeout:  30,
	}

	if err := fm.OpenRule(ctx); err != nil {
		t.Fatalf("OpenRule error: %v", err)
	}

	// Open command SHOULD have been executed since check failed.
	if _, err := os.Stat(openLog); err != nil {
		t.Error("open command should have been executed when check fails")
	}

	fm.Shutdown()
}

func TestTimerRefreshOnDuplicateRule(t *testing.T) {
	cfg := actionsConfig{
		Open:  "true",
		Close: "true",
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	ctx := templateContext{
		SourceIP: "10.0.0.1",
		Proto:    "tcp",
		Port:     "22",
		Timeout:  30,
	}

	// Open twice — should replace timer, not add duplicate.
	fm.OpenRule(ctx)
	fm.OpenRule(ctx)

	if fm.ActiveRuleCount() != 1 {
		t.Errorf("active rules = %d, want 1 (should not duplicate)", fm.ActiveRuleCount())
	}

	fm.Shutdown()
}

func TestShutdownClosesAllRules(t *testing.T) {
	dir := t.TempDir()
	closeLog := filepath.Join(dir, "close.log")

	cfg := actionsConfig{
		Open:     "true",
		Close:    "echo close {{.SourceIP}} >> " + closeLog,
		Shutdown: "echo shutdown >> " + filepath.Join(dir, "shutdown.log"),
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	// Open two rules.
	fm.OpenRule(templateContext{SourceIP: "10.0.0.1", Proto: "tcp", Port: "22", Timeout: 300})
	fm.OpenRule(templateContext{SourceIP: "10.0.0.2", Proto: "tcp", Port: "443", Timeout: 300})

	if fm.ActiveRuleCount() != 2 {
		t.Fatalf("active rules = %d, want 2", fm.ActiveRuleCount())
	}

	fm.Shutdown()

	if fm.ActiveRuleCount() != 0 {
		t.Errorf("active rules after shutdown = %d, want 0", fm.ActiveRuleCount())
	}

	// Verify close was called for each rule.
	data, _ := os.ReadFile(closeLog)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("close log has %d lines, want 2", len(lines))
	}

	// Verify shutdown command was executed.
	shutdownLog := filepath.Join(dir, "shutdown.log")
	if _, err := os.Stat(shutdownLog); err != nil {
		t.Error("shutdown command should have been executed")
	}
}

func TestExecuteCommand(t *testing.T) {
	fm, _ := newActionsManager(actionsConfig{}, testActionLogger())
	if err := fm.ExecuteCommand("true", ""); err != nil {
		t.Errorf("ExecuteCommand error: %v", err)
	}
}

func TestExecuteCommandFailure(t *testing.T) {
	fm, _ := newActionsManager(actionsConfig{}, testActionLogger())
	if err := fm.ExecuteCommand("false", ""); err == nil {
		t.Error("expected ExecuteCommand to fail")
	}
}

func TestParseAccessMsg(t *testing.T) {
	tests := []struct {
		input     string
		wantProto string
		wantPort  string
	}{
		{"192.168.1.1,tcp/22", "tcp", "22"},
		{"10.0.0.1,udp/53", "udp", "53"},
		{"10.0.0.1,tcp/443", "tcp", "443"},
		{"bad-format", "", ""},
		{"10.0.0.1,tcp", "tcp", ""},
	}

	for _, tc := range tests {
		proto, port := parseAccessMsg(tc.input)
		if proto != tc.wantProto || port != tc.wantPort {
			t.Errorf("parseAccessMsg(%q) = (%q, %q), want (%q, %q)",
				tc.input, proto, port, tc.wantProto, tc.wantPort)
		}
	}
}

func TestAllowsPort(t *testing.T) {
	stanza := &accessStanza{OpenPorts: []string{"tcp/22", "tcp/443"}}

	if !allowsPort(stanza, "tcp", "22") {
		t.Error("should allow tcp/22")
	}
	if !allowsPort(stanza, "tcp", "443") {
		t.Error("should allow tcp/443")
	}
	if allowsPort(stanza, "tcp", "80") {
		t.Error("should not allow tcp/80")
	}
	if allowsPort(stanza, "udp", "22") {
		t.Error("should not allow udp/22")
	}

	// Empty open_ports allows all.
	emptyStanza := &accessStanza{}
	if !allowsPort(emptyStanza, "tcp", "9999") {
		t.Error("empty open_ports should allow any port")
	}
}

func TestEffectiveTimeout(t *testing.T) {
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	tests := []struct {
		clientTimeout uint32
		want          int
	}{
		{0, 30},   // No client timeout → use stanza default
		{60, 60},  // Client timeout within max
		{200, 120}, // Client timeout exceeds max → capped
	}

	for _, tc := range tests {
		msg := &fkospa.Message{ClientTimeout: tc.clientTimeout}
		got := effectiveTimeout(msg, stanza)
		if got != tc.want {
			t.Errorf("effectiveTimeout(clientTimeout=%d) = %d, want %d", tc.clientTimeout, got, tc.want)
		}
	}
}

func TestBuildTemplateContext(t *testing.T) {
	msg := &fkospa.Message{
		AccessMsg:     "10.0.0.1,tcp/22",
		Username:      "alice",
		Timestamp:     time.Unix(1700000000, 0),
		NATAccess:     "192.168.1.100,22",
		ClientTimeout: 60,
	}
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	ctx := buildTemplateContext(msg, "10.0.0.1", stanza)

	if ctx.SourceIP != "10.0.0.1" {
		t.Errorf("SourceIP = %q", ctx.SourceIP)
	}
	if ctx.Proto != "tcp" {
		t.Errorf("Proto = %q", ctx.Proto)
	}
	if ctx.Port != "22" {
		t.Errorf("Port = %q", ctx.Port)
	}
	if ctx.Username != "alice" {
		t.Errorf("Username = %q", ctx.Username)
	}
	if ctx.Timeout != 60 {
		t.Errorf("Timeout = %d, want 60", ctx.Timeout)
	}
	if ctx.NATAccess != "192.168.1.100,22" {
		t.Errorf("NATAccess = %q", ctx.NATAccess)
	}
}
