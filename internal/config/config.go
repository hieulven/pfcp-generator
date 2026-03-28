package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for the PFCP generator.
type Config struct {
	SMF         SMFConfig         `yaml:"smf"         mapstructure:"smf"`
	UPF         UPFConfig         `yaml:"upf"         mapstructure:"upf"`
	Association AssociationConfig `yaml:"association" mapstructure:"association"`
	Session     SessionConfig     `yaml:"session"     mapstructure:"session"`
	Timing      TimingConfig      `yaml:"timing"      mapstructure:"timing"`
	Input       InputConfig       `yaml:"input"       mapstructure:"input"`
	Logging     LoggingConfig     `yaml:"logging"     mapstructure:"logging"`
	Stats       StatsConfig       `yaml:"stats"       mapstructure:"stats"`
	Stress      StressConfig      `yaml:"stress"      mapstructure:"stress"`
}

type SMFConfig struct {
	Address     string `yaml:"address"      mapstructure:"address"`
	Port        int    `yaml:"port"         mapstructure:"port"`
	NodeID      string `yaml:"node_id"      mapstructure:"node_id"`
	SourcePorts int    `yaml:"source_ports" mapstructure:"source_ports"`
}

type UPFConfig struct {
	Address string `yaml:"address" mapstructure:"address"`
	Port    int    `yaml:"port"    mapstructure:"port"`
}

type AssociationConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
}

type SessionConfig struct {
	SEIDStart      uint64   `yaml:"seid_start"       mapstructure:"seid_start"`
	SEIDStrategy   string   `yaml:"seid_strategy"    mapstructure:"seid_strategy"`
	UEIPPool       string   `yaml:"ue_ip_pool"       mapstructure:"ue_ip_pool"`
	UEIPPools      []string `yaml:"ue_ip_pools"      mapstructure:"ue_ip_pools"`
	StripIPv6      bool     `yaml:"strip_ipv6"       mapstructure:"strip_ipv6"`
	StripVendorIEs bool     `yaml:"strip_vendor_ies" mapstructure:"strip_vendor_ies"`
	CleanupOnExit  bool     `yaml:"cleanup_on_exit"  mapstructure:"cleanup_on_exit"`
}

type TimingConfig struct {
	MessageIntervalMs int `yaml:"message_interval_ms"  mapstructure:"message_interval_ms"`
	ResponseTimeoutMs int `yaml:"response_timeout_ms"  mapstructure:"response_timeout_ms"`
	MaxRetries        int `yaml:"max_retries"          mapstructure:"max_retries"`
	RepeatIntervalMs  int `yaml:"repeat_interval_ms"   mapstructure:"repeat_interval_ms"`
}

type InputConfig struct {
	PcapFile    string `yaml:"pcap_file"    mapstructure:"pcap_file"`
	RepeatCount int    `yaml:"repeat_count" mapstructure:"repeat_count"`
}

type LoggingConfig struct {
	Level   string `yaml:"level"   mapstructure:"level"`
	File    string `yaml:"file"    mapstructure:"file"`
	Console bool   `yaml:"console" mapstructure:"console"`
}

type StatsConfig struct {
	Enabled           bool   `yaml:"enabled"             mapstructure:"enabled"`
	ReportIntervalSec int    `yaml:"report_interval_sec" mapstructure:"report_interval_sec"`
	ExportFile        string `yaml:"export_file"         mapstructure:"export_file"`
}

// StressConfig configures the high-performance stress test mode.
type StressConfig struct {
	Enabled        bool `yaml:"enabled"         mapstructure:"enabled"`
	TPS            int  `yaml:"tps"             mapstructure:"tps"`
	ActiveSessions int  `yaml:"active_sessions" mapstructure:"active_sessions"`
	DurationSec    int  `yaml:"duration_sec"    mapstructure:"duration_sec"`
}

// AllPools returns the list of UE IP pool CIDRs. If UEIPPools is set, it takes
// precedence. Otherwise the single UEIPPool value is used.
func (s *SessionConfig) AllPools() []string {
	if len(s.UEIPPools) > 0 {
		return s.UEIPPools
	}
	if s.UEIPPool != "" {
		return []string{s.UEIPPool}
	}
	return nil
}

// SetDefaults configures default values for the configuration.
func SetDefaults(v *viper.Viper) {
	v.SetDefault("smf.port", 8805)
	v.SetDefault("smf.source_ports", 1)
	v.SetDefault("upf.port", 8805)
	v.SetDefault("association.enabled", true)
	v.SetDefault("session.seid_start", 1)
	v.SetDefault("session.seid_strategy", "sequential")
	v.SetDefault("session.strip_ipv6", true)
	v.SetDefault("session.strip_vendor_ies", true)
	v.SetDefault("session.cleanup_on_exit", false)
	v.SetDefault("input.repeat_count", 1)
	v.SetDefault("timing.message_interval_ms", 100)
	v.SetDefault("timing.response_timeout_ms", 5000)
	v.SetDefault("timing.max_retries", 3)
	v.SetDefault("timing.repeat_interval_ms", 0)
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.console", true)
	v.SetDefault("stats.enabled", true)
	v.SetDefault("stats.report_interval_sec", 10)
	v.SetDefault("stress.enabled", false)
	v.SetDefault("stress.tps", 50000)
	v.SetDefault("stress.active_sessions", 10000)
	v.SetDefault("stress.duration_sec", 0)
}

// Load reads configuration from a YAML file and returns a Config.
func Load(configFile string) (*Config, error) {
	v := viper.New()
	SetDefaults(v)

	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configFile, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// LoadWithViper reads configuration using an existing viper instance (for CLI flag binding).
func LoadWithViper(v *viper.Viper) (*Config, error) {
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &cfg, nil
}

// Summary returns a human-readable summary of the configuration.
func (c *Config) Summary() string {
	var sb strings.Builder
	sb.WriteString("Configuration:\n")
	if c.SMF.SourcePorts > 1 {
		sb.WriteString(fmt.Sprintf("  SMF:           %s:%d-%d (%d ports)\n", c.SMF.Address, c.SMF.Port, c.SMF.Port+c.SMF.SourcePorts-1, c.SMF.SourcePorts))
	} else {
		sb.WriteString(fmt.Sprintf("  SMF:           %s:%d\n", c.SMF.Address, c.SMF.Port))
	}
	sb.WriteString(fmt.Sprintf("  UPF:           %s:%d\n", c.UPF.Address, c.UPF.Port))
	sb.WriteString(fmt.Sprintf("  Association:   enabled=%v\n", c.Association.Enabled))
	sb.WriteString(fmt.Sprintf("  PCAP:          %s\n", c.Input.PcapFile))
	pools := c.Session.AllPools()
	if len(pools) == 1 {
		sb.WriteString(fmt.Sprintf("  UE Pool:       %s\n", pools[0]))
	} else {
		sb.WriteString(fmt.Sprintf("  UE Pools:      %s (%d pools)\n", strings.Join(pools, ", "), len(pools)))
	}
	sb.WriteString(fmt.Sprintf("  Strip IPv6:    %v\n", c.Session.StripIPv6))
	sb.WriteString(fmt.Sprintf("  SEID Start:    %d (%s)\n", c.Session.SEIDStart, c.Session.SEIDStrategy))
	if c.Stress.Enabled {
		sb.WriteString("  Mode:          STRESS TEST\n")
		sb.WriteString(fmt.Sprintf("  Target TPS:    %d\n", c.Stress.TPS))
		sb.WriteString(fmt.Sprintf("  Active Sess:   %d\n", c.Stress.ActiveSessions))
		if c.Stress.DurationSec > 0 {
			sb.WriteString(fmt.Sprintf("  Duration:      %ds\n", c.Stress.DurationSec))
		} else {
			sb.WriteString("  Duration:      unlimited (Ctrl+C to stop)\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Msg Interval:  %dms\n", c.Timing.MessageIntervalMs))
		if c.Input.RepeatCount == 0 {
			sb.WriteString("  Repeat:        infinite\n")
		} else {
			sb.WriteString(fmt.Sprintf("  Repeat:        %d time(s)\n", c.Input.RepeatCount))
		}
		if c.Timing.RepeatIntervalMs > 0 {
			sb.WriteString(fmt.Sprintf("  Repeat Delay:  %dms\n", c.Timing.RepeatIntervalMs))
		}
	}
	sb.WriteString(fmt.Sprintf("  Timeout:       %dms (retries: %d)\n", c.Timing.ResponseTimeoutMs, c.Timing.MaxRetries))
	sb.WriteString(fmt.Sprintf("  Cleanup:       %v\n", c.Session.CleanupOnExit))
	return sb.String()
}
