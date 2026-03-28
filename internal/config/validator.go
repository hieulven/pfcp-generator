package config

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	var errs []string

	// SMF address must be a valid IP
	if net.ParseIP(c.SMF.Address) == nil {
		errs = append(errs, fmt.Sprintf("smf.address must be a valid IP address, got %q", c.SMF.Address))
	}

	// SMF port must be valid
	if c.SMF.Port <= 0 || c.SMF.Port > 65535 {
		errs = append(errs, fmt.Sprintf("smf.port must be between 1 and 65535, got %d", c.SMF.Port))
	}

	// Source ports must be valid
	if c.SMF.SourcePorts < 1 || c.SMF.SourcePorts > 256 {
		errs = append(errs, fmt.Sprintf("smf.source_ports must be between 1 and 256, got %d", c.SMF.SourcePorts))
	} else if c.SMF.Port+c.SMF.SourcePorts-1 > 65535 {
		errs = append(errs, fmt.Sprintf("smf.port + smf.source_ports exceeds port range: %d + %d", c.SMF.Port, c.SMF.SourcePorts))
	}

	// UPF address must be a valid IP
	if net.ParseIP(c.UPF.Address) == nil {
		errs = append(errs, fmt.Sprintf("upf.address must be a valid IP address, got %q", c.UPF.Address))
	}

	// UPF port must be valid
	if c.UPF.Port <= 0 || c.UPF.Port > 65535 {
		errs = append(errs, fmt.Sprintf("upf.port must be between 1 and 65535, got %d", c.UPF.Port))
	}

	// PCAP file must exist
	if c.Input.PcapFile == "" {
		errs = append(errs, "input.pcap_file must be specified")
	} else if _, err := os.Stat(c.Input.PcapFile); os.IsNotExist(err) {
		errs = append(errs, fmt.Sprintf("pcap file not found: %s", c.Input.PcapFile))
	}

	// UE IP pool(s) must be valid CIDR
	pools := c.Session.AllPools()
	if len(pools) == 0 {
		errs = append(errs, "session.ue_ip_pool or session.ue_ip_pools must be specified")
	} else {
		for _, cidr := range pools {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				errs = append(errs, fmt.Sprintf("invalid UE IP pool CIDR %q: %v", cidr, err))
			}
		}
	}

	// SEID start must be > 0
	if c.Session.SEIDStart == 0 {
		errs = append(errs, "session.seid_start must be > 0")
	}

	// SEID strategy must be known
	if c.Session.SEIDStrategy != "sequential" && c.Session.SEIDStrategy != "random" {
		errs = append(errs, fmt.Sprintf("session.seid_strategy must be 'sequential' or 'random', got %q", c.Session.SEIDStrategy))
	}

	// Response timeout must be positive
	if c.Timing.ResponseTimeoutMs <= 0 {
		errs = append(errs, "timing.response_timeout_ms must be > 0")
	}

	// Max retries must be non-negative
	if c.Timing.MaxRetries < 0 {
		errs = append(errs, "timing.max_retries must be >= 0")
	}

	// Log level must be valid
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		errs = append(errs, fmt.Sprintf("logging.level must be one of debug/info/warn/error, got %q", c.Logging.Level))
	}

	// Stress test validation
	if c.Stress.Enabled {
		if c.Stress.TPS <= 0 {
			errs = append(errs, "stress.tps must be > 0")
		}
		if c.Stress.ActiveSessions <= 0 {
			errs = append(errs, "stress.active_sessions must be > 0")
		}
		if c.Stress.DurationSec < 0 {
			errs = append(errs, "stress.duration_sec must be >= 0")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration errors:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
