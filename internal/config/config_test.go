package config

import (
	"os"
	"testing"
)

func TestConfigLoadAndValidation(t *testing.T) {
	yamlContent := `
server:
  listen_addr: "127.0.0.1:1053"
  read_timeout: 2s
  write_timeout: 2s

upstream:
  servers:
    - "https://dns.quad9.net/dns-query"
  timeout: 3s
  strategy: "round_robin"

blocking:
  enabled: true
  block_mode: "zero_ip"
  custom_zero_ipv4: "0.0.0.0"
  custom_zero_ipv6: "::"
  blacklist:
    - "ads.bad.com"
  whitelist:
    - "safe.bad.com"

cache:
  enabled: true
  size: 5000

opsec:
  zero_log: true
  log_level: "debug"
`
	tmpFile, err := os.CreateTemp("", "tuxdns_config_*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(yamlContent); err != nil {
		t.Fatalf("failed to write config content: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.Server.ListenAddr != "127.0.0.1:1053" {
		t.Errorf("expected listen_addr '127.0.0.1:1053', got %s", cfg.Server.ListenAddr)
	}
	if len(cfg.Blocking.Blacklist) != 1 || cfg.Blocking.Blacklist[0] != "ads.bad.com" {
		t.Errorf("unexpected blacklist: %v", cfg.Blocking.Blacklist)
	}
	if !cfg.OpSec.ZeroLog {
		t.Errorf("expected zero_log to be true")
	}
}

func TestConfigValidationInvalidMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Blocking.BlockMode = "invalid_mode"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for invalid block_mode, got nil")
	}
}
