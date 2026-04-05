package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

const (
	defaultConfigFile = "/etc/fwknop/server.yaml"
	defaultAccessFile = "/etc/fwknop/access.yaml"
	defaultPIDFile    = "/var/run/fwknop/fwknopd.pid"
	defaultRunDir     = "/var/run/fwknop"
	defaultLogFile    = "/var/log/fwknop/fwknopd.log"
	defaultUDPPort    = 62201
	defaultBindAddr   = "0.0.0.0"
	defaultMaxAge     = 120
	defaultActionDir  = "/etc/fwknop/actions"
	serverVersion     = "0.1.0"
)

// serverConfig holds all resolved configuration for fwknopd.
type serverConfig struct {
	// Network
	UDPPort     int    `koanf:"udp_port"`
	BindAddress string `koanf:"bind_address"`

	// Logging
	LogFile       string `koanf:"log_file"`
	SyslogIdent   string `koanf:"syslog_identity"`
	SyslogFacility string `koanf:"syslog_facility"`
	Verbose       bool   `koanf:"verbose"`

	// Daemon
	PIDFile string `koanf:"pid_file"`
	RunDir  string `koanf:"run_dir"`

	// SPA Processing
	MaxSPAPacketAge int `koanf:"max_spa_packet_age"`

	// Actions
	Actions        actionsConfig `koanf:"actions"`
	ActionTemplate string        `koanf:"action_template"`
	ActionDir      string        `koanf:"action_dir"`

	// Files (from CLI)
	ConfigFile string `koanf:"config_file"`
	AccessFile string `koanf:"access_file"`

	// Modes (CLI only)
	Foreground  bool `koanf:"foreground"`
	Test        bool `koanf:"test"`
	DumpConfig  bool `koanf:"dump_config"`
	Kill        bool `koanf:"kill"`
	Restart     bool `koanf:"restart"`
	Status      bool `koanf:"status"`
	ShowVersion bool `koanf:"version"`
}

func setupServerFlags() *pflag.FlagSet {
	f := pflag.NewFlagSet("fwknopd", pflag.ContinueOnError)
	f.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: fwknopd [options]\n\nOptions:\n")
		f.PrintDefaults()
	}

	f.StringP("config-file", "c", defaultConfigFile, "Server config YAML file")
	f.StringP("access-file", "a", defaultAccessFile, "Access rules YAML file")
	f.BoolP("dump-config", "D", false, "Dump current config and exit")
	f.BoolP("foreground", "f", false, "Run in foreground (don't daemonize)")
	f.BoolP("help", "h", false, "Print usage")
	f.BoolP("kill", "K", false, "Kill running fwknopd")
	f.StringP("pid-file", "p", "", "PID file path")
	f.BoolP("restart", "R", false, "Restart running fwknopd")
	f.BoolP("status", "S", false, "Show status of running fwknopd")
	f.BoolP("test", "t", false, "Test mode (parse packets, log only)")
	f.BoolP("verbose", "v", false, "Verbose mode")
	f.BoolP("version", "V", false, "Print version")

	return f
}

// loadServerConfig builds the layered config: YAML file → env vars → CLI flags.
func loadServerConfig(args []string) (*serverConfig, error) {
	k := koanf.New(".")
	flags := setupServerFlags()

	if err := flags.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			os.Exit(0)
		}
		return nil, err
	}

	help, _ := flags.GetBool("help")
	if help {
		flags.Usage()
		os.Exit(0)
	}

	// Set defaults.
	k.Set("udp_port", defaultUDPPort)
	k.Set("bind_address", defaultBindAddr)
	k.Set("log_file", defaultLogFile)
	k.Set("syslog_identity", "fwknopd")
	k.Set("syslog_facility", "daemon")
	k.Set("pid_file", defaultPIDFile)
	k.Set("run_dir", defaultRunDir)
	k.Set("max_spa_packet_age", defaultMaxAge)
	k.Set("action_dir", defaultActionDir)
	k.Set("config_file", defaultConfigFile)
	k.Set("access_file", defaultAccessFile)

	// Step 1: Determine config file path from CLI (before loading YAML).
	configFile, _ := flags.GetString("config-file")

	// Step 2: Load YAML config file (if it exists).
	if _, err := os.Stat(configFile); err == nil {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("loading config file %s: %w", configFile, err)
		}
	}

	// Step 3: Load env vars (prefix FWKNOPD_).
	if err := k.Load(env.Provider("FWKNOPD_", ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "FWKNOPD_"))
	}), nil); err != nil {
		return nil, fmt.Errorf("loading env vars: %w", err)
	}

	// Step 4: Load CLI flags (highest priority).
	if err := k.Load(posflag.ProviderWithFlag(flags, ".", k, func(f *pflag.Flag) (string, interface{}) {
		key := strings.ReplaceAll(f.Name, "-", "_")
		switch f.Value.Type() {
		case "bool":
			val, _ := flags.GetBool(f.Name)
			return key, val
		case "int":
			val, _ := flags.GetInt(f.Name)
			return key, val
		default:
			return key, f.Value.String()
		}
	}), nil); err != nil {
		return nil, fmt.Errorf("loading CLI flags: %w", err)
	}

	var cfg serverConfig
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	// Override from CLI if explicitly set.
	if flags.Changed("config-file") {
		cfg.ConfigFile = configFile
	}
	if af, _ := flags.GetString("access-file"); flags.Changed("access-file") {
		cfg.AccessFile = af
	}
	if pf, _ := flags.GetString("pid-file"); flags.Changed("pid-file") {
		cfg.PIDFile = pf
	}

	return &cfg, nil
}
