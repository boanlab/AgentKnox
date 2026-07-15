// SPDX-License-Identifier: Apache-2.0
// Package config loads AgentKnox configuration: flag → viper defaults →
// agentknox.yaml (./ or /etc/agentknox/) → AGENTKNOX_* env overrides.
package config

import (
	"strings"

	"github.com/spf13/viper"
)

// Mode is the deployment context (informational). AgentKnox always monitors
// host-native agent processes and loads policies from a local directory; it runs
// either as a systemd daemon or as a privileged Docker container (pid/network
// host). Agents themselves run directly on the host, never inside AgentKnox.
type Mode string

const (
	ModeWorkstation Mode = "workstation" // systemd daemon on the host
	ModeDocker      Mode = "docker"      // AgentKnox in a privileged host container
	ModeHost        Mode = "host"        // CLI-only (dev/test)
)

// Config is the single global configuration struct.
type Config struct {
	Mode      Mode   `mapstructure:"mode"`
	NodeName  string `mapstructure:"nodeName"`
	PolicyDir string `mapstructure:"policyDir"`

	// GRPCAddr is the gRPC listen address for the AgentKnoxExport service. The
	// stream carries captured prompt and response bodies and the service has no
	// transport security and no authentication, so this binds to loopback.
	// Widening it publishes those bodies to anyone who can reach the port;
	// front it with an authenticated tunnel instead.
	GRPCAddr string `mapstructure:"grpcAddr"`

	// Storage
	WALDir     string `mapstructure:"walDir"`
	ArchiveDir string `mapstructure:"archiveDir"` // scripts/code the agent writes & runs

	// AggregatorAddr, when set, forwards events to a central aggregator (multi-host
	// deployments) over gRPC. Empty = local-only. Hot-reloadable: edit the config
	// file and the daemon starts/stops/redirects forwarding without a restart.
	AggregatorAddr string `mapstructure:"aggregatorAddr"`

	// File is the resolved config file path (empty if none); watched for hot-reload
	// of AggregatorAddr. Not settable via config.
	File string `mapstructure:"-"`

	// Semantic capture
	SemanticEnabled bool   `mapstructure:"semanticEnabled"`
	CapturePrompts  bool   `mapstructure:"capturePrompts"` // default true; false redacts bodies
	OffsetDBPath    string `mapstructure:"offsetDBPath"`

	// Session detection
	AgentSignatures []string `mapstructure:"agentSignatures"`
	CgroupParent    string   `mapstructure:"cgroupParent"`
	// ManageCgroup moves detected agents into a dedicated managed cgroup. Default
	// false = shared/non-invasive (use the process's existing cgroup id as the
	// key; enforcement is scoped to the agent's pid tree to avoid over-applying
	// to co-resident processes that share the cgroup).
	ManageCgroup bool `mapstructure:"manageCgroup"`

	// Enforcement
	EnforcerBackend string `mapstructure:"enforcerBackend"` // auto|bpf-lsm|userspace
	DryRun          bool   `mapstructure:"dryRun"`          // observe, never block

	LogLevel string `mapstructure:"logLevel"`
}

// Load builds the Config from defaults + optional file + env.
func Load() (*Config, error) {
	v := viper.New()
	v.SetDefault("mode", string(ModeWorkstation))
	v.SetDefault("nodeName", hostnameOr("localhost"))
	v.SetDefault("policyDir", "/etc/agentknox/policies")
	v.SetDefault("grpcAddr", "127.0.0.1:36920")
	v.SetDefault("walDir", "/var/lib/agentknox/wal")
	v.SetDefault("archiveDir", "/var/lib/agentknox/scripts")
	v.SetDefault("semanticEnabled", true)
	v.SetDefault("capturePrompts", true) // capture raw prompt/response bodies (stored locally in WAL)
	v.SetDefault("offsetDBPath", "/etc/agentknox/offsetdb")
	v.SetDefault("agentSignatures", []string{"claude", "codex", "crush", "gemini", "copilot"})
	v.SetDefault("cgroupParent", "agentknox.slice")
	v.SetDefault("manageCgroup", false)
	v.SetDefault("enforcerBackend", "auto")
	v.SetDefault("dryRun", false)
	v.SetDefault("logLevel", "info")
	v.SetDefault("aggregatorAddr", "")

	v.SetConfigName("agentknox")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/agentknox/")
	_ = v.ReadInConfig() // optional

	v.SetEnvPrefix("AGENTKNOX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var c Config
	if err := v.Unmarshal(&c); err != nil {
		return nil, err
	}
	c.File = v.ConfigFileUsed()
	return &c, nil
}

// Reload re-reads the config file and returns the fresh config. Used by the
// daemon to hot-apply the aggregator setting on config-file change.
func Reload() (*Config, error) { return Load() }

func hostnameOr(def string) string {
	if h, err := osHostname(); err == nil && h != "" {
		return h
	}
	return def
}
