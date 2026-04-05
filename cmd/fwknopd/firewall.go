package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

// firewallConfig holds command templates for each lifecycle step.
// All fields are optional — omit or leave empty to skip that step.
type firewallConfig struct {
	Validate string `koanf:"validate" yaml:"validate"`
	Init     string `koanf:"init"     yaml:"init"`
	Check    string `koanf:"check"    yaml:"check"`
	Open     string `koanf:"open"     yaml:"open"`
	Close    string `koanf:"close"    yaml:"close"`
	Shutdown string `koanf:"shutdown" yaml:"shutdown"`
}

// templateContext holds the data available to check/open/close templates.
type templateContext struct {
	SourceIP  string // UDP packet source IP
	Proto     string // Protocol from access message (tcp, udp)
	Port      string // Port number from access message
	Username  string // Username from SPA message
	Timestamp int64  // Unix timestamp from SPA message
	Timeout   int    // Effective rule timeout in seconds
	AccessMsg string // Raw access message string
	NATAccess string // NAT access string (if present)
}

// activeRule tracks a firewall rule that was opened and will be closed on timeout.
type activeRule struct {
	ctx   templateContext
	timer *time.Timer
}

// firewallManager manages firewall command execution and rule lifecycle.
type firewallManager struct {
	cfg         firewallConfig
	logger      *spaLogger
	mu          sync.Mutex
	activeRules map[string]*activeRule // key: "srcIP/proto/port"
	checkTmpl   *template.Template
	openTmpl    *template.Template
	closeTmpl   *template.Template
}

// newFirewallManager creates and initializes a firewall manager.
// Returns an error if any command template fails to parse.
func newFirewallManager(cfg firewallConfig, logger *spaLogger) (*firewallManager, error) {
	fm := &firewallManager{
		cfg:         cfg,
		logger:      logger,
		activeRules: make(map[string]*activeRule),
	}

	var err error
	if cfg.Check != "" {
		fm.checkTmpl, err = template.New("check").Parse(cfg.Check)
		if err != nil {
			return nil, fmt.Errorf("parsing check template: %w", err)
		}
	}
	if cfg.Open != "" {
		fm.openTmpl, err = template.New("open").Parse(cfg.Open)
		if err != nil {
			return nil, fmt.Errorf("parsing open template: %w", err)
		}
	}
	if cfg.Close != "" {
		fm.closeTmpl, err = template.New("close").Parse(cfg.Close)
		if err != nil {
			return nil, fmt.Errorf("parsing close template: %w", err)
		}
	}

	return fm, nil
}

// Validate executes the validate command to verify required tools exist.
// Returns an error if the command fails (non-zero exit).
func (fm *firewallManager) Validate() error {
	if fm.cfg.Validate == "" {
		return nil
	}
	fm.logger.Info("Running firewall validate command...")
	if err := runCommand(fm.cfg.Validate); err != nil {
		return fmt.Errorf("firewall validate failed: %w", err)
	}
	return nil
}

// Init executes the init command to set up firewall chains/sets.
func (fm *firewallManager) Init() error {
	if fm.cfg.Init == "" {
		return nil
	}
	fm.logger.Info("Running firewall init command...")
	if err := runCommand(fm.cfg.Init); err != nil {
		return fmt.Errorf("firewall init failed: %w", err)
	}
	return nil
}

// OpenRule checks whether a rule already exists, opens it if not, and schedules
// a close timer. If a rule with the same key already exists, its timer is reset.
func (fm *firewallManager) OpenRule(ctx templateContext) error {
	ruleKey := fmt.Sprintf("%s/%s/%s", ctx.SourceIP, ctx.Proto, ctx.Port)

	// Check if rule already exists.
	if fm.checkTmpl != nil {
		cmd, err := renderTemplate(fm.checkTmpl, ctx)
		if err != nil {
			return fmt.Errorf("rendering check template: %w", err)
		}
		if err := runCommand(cmd); err == nil {
			fm.logger.Info("Rule already exists for %s, refreshing timeout", ruleKey)
			fm.refreshTimer(ruleKey, ctx)
			return nil
		}
		// Non-zero exit means rule doesn't exist — proceed to open.
	}

	// Open the rule.
	if fm.openTmpl != nil {
		cmd, err := renderTemplate(fm.openTmpl, ctx)
		if err != nil {
			return fmt.Errorf("rendering open template: %w", err)
		}
		if err := runCommand(cmd); err != nil {
			return fmt.Errorf("open command failed for %s: %w", ruleKey, err)
		}
		fm.logger.Info("Opened firewall rule for %s (timeout: %ds)", ruleKey, ctx.Timeout)
	}

	// Schedule close timer.
	fm.scheduleClose(ruleKey, ctx)
	return nil
}

// CloseRule executes the close command and removes the rule from tracking.
func (fm *firewallManager) CloseRule(ctx templateContext) {
	ruleKey := fmt.Sprintf("%s/%s/%s", ctx.SourceIP, ctx.Proto, ctx.Port)

	if fm.closeTmpl != nil {
		cmd, err := renderTemplate(fm.closeTmpl, ctx)
		if err != nil {
			fm.logger.Error("Rendering close template for %s: %v", ruleKey, err)
		} else if err := runCommand(cmd); err != nil {
			fm.logger.Error("Close command failed for %s: %v", ruleKey, err)
		} else {
			fm.logger.Info("Closed firewall rule for %s", ruleKey)
		}
	}

	fm.mu.Lock()
	delete(fm.activeRules, ruleKey)
	fm.mu.Unlock()
}

// ExecuteCommand runs a command from a CommandMsg SPA request.
func (fm *firewallManager) ExecuteCommand(cmdStr string, user string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if user != "" {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("su -c '%s' %s", cmdStr, user))
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
	}

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		fm.logger.Info("Command output: %s", strings.TrimSpace(string(output)))
	}
	return err
}

// Shutdown stops all pending timers, closes all active rules, and runs the
// shutdown command template.
func (fm *firewallManager) Shutdown() {
	fm.mu.Lock()
	rules := make(map[string]*activeRule, len(fm.activeRules))
	for k, v := range fm.activeRules {
		rules[k] = v
		v.timer.Stop()
	}
	fm.activeRules = make(map[string]*activeRule)
	fm.mu.Unlock()

	// Close each active rule individually.
	for ruleKey, rule := range rules {
		if fm.closeTmpl != nil {
			cmd, err := renderTemplate(fm.closeTmpl, rule.ctx)
			if err != nil {
				fm.logger.Error("Rendering close template for %s during shutdown: %v", ruleKey, err)
				continue
			}
			if err := runCommand(cmd); err != nil {
				fm.logger.Error("Close command failed for %s during shutdown: %v", ruleKey, err)
			} else {
				fm.logger.Info("Closed firewall rule for %s (shutdown)", ruleKey)
			}
		}
	}

	// Run the shutdown template (e.g., flush chains).
	if fm.cfg.Shutdown != "" {
		fm.logger.Info("Running firewall shutdown command...")
		if err := runCommand(fm.cfg.Shutdown); err != nil {
			fm.logger.Error("Firewall shutdown command failed: %v", err)
		}
	}
}

// ActiveRuleCount returns the number of currently active firewall rules.
func (fm *firewallManager) ActiveRuleCount() int {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return len(fm.activeRules)
}

// scheduleClose creates a timer that fires CloseRule after the timeout.
func (fm *firewallManager) scheduleClose(ruleKey string, ctx templateContext) {
	timeout := time.Duration(ctx.Timeout) * time.Second

	fm.mu.Lock()
	defer fm.mu.Unlock()

	// If a rule with this key already exists, stop the old timer.
	if existing, ok := fm.activeRules[ruleKey]; ok {
		existing.timer.Stop()
	}

	timer := time.AfterFunc(timeout, func() {
		fm.CloseRule(ctx)
	})

	fm.activeRules[ruleKey] = &activeRule{ctx: ctx, timer: timer}
}

// refreshTimer resets the timer for an existing rule without re-opening it.
func (fm *firewallManager) refreshTimer(ruleKey string, ctx templateContext) {
	fm.scheduleClose(ruleKey, ctx)
}

// allowsPort checks if the requested proto/port is permitted by the stanza's
// open_ports list. An empty list allows all ports.
func allowsPort(stanza *accessStanza, proto, port string) bool {
	if len(stanza.OpenPorts) == 0 {
		return true
	}
	requested := proto + "/" + port
	for _, allowed := range stanza.OpenPorts {
		if strings.EqualFold(allowed, requested) {
			return true
		}
	}
	return false
}

// buildTemplateContext creates a templateContext from a decoded SPA message.
func buildTemplateContext(msg *fkospa.Message, srcIP string, stanza *accessStanza) templateContext {
	proto, port := parseAccessMsg(msg.AccessMsg)
	timeout := effectiveTimeout(msg, stanza)

	return templateContext{
		SourceIP:  srcIP,
		Proto:     proto,
		Port:      port,
		Username:  msg.Username,
		Timestamp: msg.Timestamp.Unix(),
		Timeout:   timeout,
		AccessMsg: msg.AccessMsg,
		NATAccess: msg.NATAccess,
	}
}

// effectiveTimeout computes the rule timeout from the SPA message and stanza.
func effectiveTimeout(msg *fkospa.Message, stanza *accessStanza) int {
	if msg.ClientTimeout > 0 {
		ct := int(msg.ClientTimeout)
		if stanza.MaxFWTimeout > 0 && ct > stanza.MaxFWTimeout {
			return stanza.MaxFWTimeout
		}
		return ct
	}
	return stanza.FWAccessTimeout
}

// parseAccessMsg extracts proto and port from an access message like "IP,tcp/22".
func parseAccessMsg(accessMsg string) (proto, port string) {
	// Format: "IP,proto/port"
	commaIdx := strings.Index(accessMsg, ",")
	if commaIdx < 0 {
		return "", ""
	}
	protoPort := accessMsg[commaIdx+1:]
	slashIdx := strings.Index(protoPort, "/")
	if slashIdx < 0 {
		return protoPort, ""
	}
	return protoPort[:slashIdx], protoPort[slashIdx+1:]
}

// renderTemplate executes a template with the given context and returns the result.
func renderTemplate(tmpl *template.Template, ctx templateContext) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// runCommand executes a command string via /bin/sh -c and returns any error.
func runCommand(cmdStr string) error {
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return err
	}
	return nil
}
