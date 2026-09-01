package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the full configuration structure of TuxDNS-Hole.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Upstream UpstreamConfig `yaml:"upstream"`
	Blocking BlockingConfig `yaml:"blocking"`
	Cache    CacheConfig    `yaml:"cache"`
	OpSec    OpSecConfig    `yaml:"opsec"`
}

// ServerConfig contains parameters for the local DNS listeners (supports IPv4 and IPv6 dual-stack).
type ServerConfig struct {
	// ListenAddrs defines one or multiple listen addresses (e.g. ["127.0.0.1:53", "[::1]:53"]).
	ListenAddrs []string `yaml:"listen_addrs"`
	// ListenAddr is maintained for backward compatibility (e.g. "127.0.0.1:53" or ":53").
	ListenAddr   string        `yaml:"listen_addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`  // e.g. "3s"
	WriteTimeout time.Duration `yaml:"write_timeout"` // e.g. "3s"
	DNSSEC       bool          `yaml:"dnssec"`        // Enable DNSSEC validation & DO bit forwarding (default: true)
}

// GetListenAddrs returns normalized list of addresses to bind.
func (s *ServerConfig) GetListenAddrs() []string {
	if len(s.ListenAddrs) > 0 {
		return s.ListenAddrs
	}
	if s.ListenAddr != "" {
		return []string{s.ListenAddr}
	}
	return []string{"127.0.0.1:53", "[::1]:53"}
}

// UpstreamConfig defines upstream DNS resolvers, bootstrap IPs, and routing strategy.
type UpstreamConfig struct {
	Servers      []string            `yaml:"servers"`       // e.g. ["https://dns.quad9.net/dns-query", "9.9.9.9:53"]
	BootstrapIPs []string            `yaml:"bootstrap_ips"` // Global bootstrap IPs for DoH cold-start (e.g. ["9.9.9.9", "1.1.1.1"])
	BootstrapMap map[string][]string `yaml:"bootstrap_map"` // Explicit per-host bootstrap IPs (e.g. "dns.quad9.net": ["9.9.9.9", "149.112.112.112"])
	Timeout      time.Duration       `yaml:"timeout"`       // Query timeout per upstream
	Strategy     string              `yaml:"strategy"`      // "round_robin", "failover", or "parallel"
}

// BlockingConfig defines sinkholing rules, lists, and formats.
type BlockingConfig struct {
	Enabled        bool          `yaml:"enabled"`
	BlockMode      string        `yaml:"block_mode"`       // "zero_ip" (0.0.0.0 / ::) or "nxdomain"
	BlocklistURLs  []string      `yaml:"blocklist_urls"`   // Remote lists to download
	BlocklistFiles []string      `yaml:"blocklist_files"`  // Local list paths
	Blacklist        []string      `yaml:"blacklist"`        // Manual custom domains to block (can include wildcards e.g. "*.telemetry.com")
	RegexBlacklist   []string      `yaml:"regex_blacklist"`  // Regex patterns to block (e.g. "^telemetry\..*")
	Whitelist        []string      `yaml:"whitelist"`        // Domains always allowed
	CNAMEUncloaking  bool          `yaml:"cname_uncloaking"` // Inspect CNAME aliases to prevent cloaked tracking (default: true)
	UpdateInterval   time.Duration `yaml:"update_interval"`  // Periodic reload interval (e.g. "24h")
	CustomZeroIPv4   string        `yaml:"custom_zero_ipv4"` // Default "0.0.0.0"
	CustomZeroIPv6   string        `yaml:"custom_zero_ipv6"` // Default "::"
	TTL              uint32        `yaml:"ttl"`               // TTL for sinkhole responses (default: 300)
}

// CacheConfig defines the in-memory LRU cache parameters.
type CacheConfig struct {
	Enabled bool          `yaml:"enabled"`
	Size    int           `yaml:"size"`    // Maximum number of entries
	MinTTL  time.Duration `yaml:"min_ttl"` // Minimum TTL floor (e.g. "60s")
	MaxTTL  time.Duration `yaml:"max_ttl"` // Maximum TTL ceiling (e.g. "86400s")
}

// OpSecConfig configures privacy and advanced anti-tracking/anti-tampering behaviors.
type OpSecConfig struct {
	ZeroLog                bool     `yaml:"zero_log"`                 // When true, client IP and individual queried domain logs are never recorded
	LogLevel               string   `yaml:"log_level"`                // "debug", "info", "warn", "error"
	EDNS0Padding           bool     `yaml:"edns0_padding"`            // Pad upstream queries to fixed block sizes (RFC 7830 / RFC 8467)
	PaddingBlockSize       int      `yaml:"padding_block_size"`       // Block size in bytes (e.g. 128)
	DNSRebindingProtection bool     `yaml:"dns_rebinding_protection"` // Strip private/local IPs from public upstream answers
	AllowedLocalDomains    []string `yaml:"allowed_local_domains"`    // Excluded from DNS rebinding checks (e.g. ["*.local", "*.lan", "router.lan"])
	DNS0x20                bool     `yaml:"dns_0x20"`                 // Randomize case of outgoing upstream queries to protect against DNS cache poisoning
	RingBufferSize         int      `yaml:"ring_buffer_size"`         // In-memory zero-disk circular query log buffer size (e.g. 1000)
}

// DefaultConfig returns safe and optimized defaults with dual-stack IPv4/IPv6 support.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddrs: []string{
				"127.0.0.1:53",
				"[::1]:53",
			},
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			DNSSEC:       true,
		},
		Upstream: UpstreamConfig{
			Servers: []string{
				"https://dns.quad9.net/dns-query",
				"https://cloudflare-dns.com/dns-query",
				"https://dns.mullvad.net/dns-query",
			},
			BootstrapIPs: []string{
				"9.9.9.9",
				"149.112.112.112",
				"1.1.1.1",
				"1.0.0.1",
				"2620:fe::fe",
				"2606:4700:4700::1111",
			},
			BootstrapMap: map[string][]string{
				"dns.quad9.net": {
					"9.9.9.9",
					"149.112.112.112",
					"2620:fe::fe",
					"2620:fe::9",
				},
				"cloudflare-dns.com": {
					"1.1.1.1",
					"1.0.0.1",
					"2606:4700:4700::1111",
					"2606:4700:4700::1001",
				},
				"dns.mullvad.net": {
					"194.242.2.2",
					"194.242.2.3",
					"2a07:e340::2",
					"2a07:e340::3",
				},
			},
			Timeout:  4 * time.Second,
			Strategy: "round_robin",
		},
		Blocking: BlockingConfig{
			Enabled:   true,
			BlockMode: "zero_ip",
			BlocklistURLs: []string{
				"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			},
			BlocklistFiles: []string{},
			Blacklist:      []string{},
			RegexBlacklist: []string{},
			Whitelist:      []string{},
			CNAMEUncloaking: true,
			UpdateInterval: 24 * time.Hour,
			CustomZeroIPv4: "0.0.0.0",
			CustomZeroIPv6: "::",
			TTL:            300,
		},
		Cache: CacheConfig{
			Enabled: true,
			Size:    10000,
			MinTTL:  60 * time.Second,
			MaxTTL:  86400 * time.Second,
		},
		OpSec: OpSecConfig{
			ZeroLog:                true,
			LogLevel:               "info",
			EDNS0Padding:           true,
			PaddingBlockSize:       128,
			DNSRebindingProtection: true,
			AllowedLocalDomains: []string{
				"*.local",
				"*.lan",
				"*.home.arpa",
				"localhost",
				"router.lan",
				"tplinkwifi.net",
				"fritz.box",
				"*.internal",
				"*.corp",
			},
			DNS0x20:        true,
			RingBufferSize: 1000,
		},
	}
}

// Load loads configuration from a YAML file, falling back to defaults for unspecified fields.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration in %q: %w", path, err)
	}

	return cfg, nil
}

// Validate checks configuration values for sanity.
func (c *Config) Validate() error {
	addrs := c.Server.GetListenAddrs()
	if len(addrs) == 0 {
		return fmt.Errorf("server.listen_addrs cannot be empty")
	}
	for _, addr := range addrs {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			// Check if only port e.g. ":53"
			if !strings.HasPrefix(addr, ":") {
				return fmt.Errorf("invalid listen address format %q (expected host:port, e.g. 127.0.0.1:53 or [::1]:53)", addr)
			}
		}
	}
	if len(c.Upstream.Servers) == 0 {
		return fmt.Errorf("upstream.servers must contain at least one upstream resolver")
	}
	if c.Blocking.BlockMode != "zero_ip" && c.Blocking.BlockMode != "nxdomain" {
		return fmt.Errorf("blocking.block_mode must be 'zero_ip' or 'nxdomain'")
	}
	if c.Blocking.CustomZeroIPv4 == "" {
		c.Blocking.CustomZeroIPv4 = "0.0.0.0"
	}
	if c.Blocking.CustomZeroIPv6 == "" {
		c.Blocking.CustomZeroIPv6 = "::"
	}
	if c.Blocking.TTL == 0 {
		c.Blocking.TTL = 300
	}
	if c.Cache.Size <= 0 {
		c.Cache.Size = 10000
	}
	if c.OpSec.PaddingBlockSize <= 0 {
		c.OpSec.PaddingBlockSize = 128
	}
	if c.OpSec.RingBufferSize < 0 {
		c.OpSec.RingBufferSize = 1000
	}
	return nil
}

