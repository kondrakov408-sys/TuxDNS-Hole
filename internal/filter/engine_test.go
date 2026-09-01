package filter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"tuxdnshole/internal/config"
)

func TestParseHosts(t *testing.T) {
	input := `
# Standard Hosts File
127.0.0.1 localhost
0.0.0.0 0.0.0.0
::1 ip6-localhost
127.0.0.1 ads.example.com evil.com # inline comment
0.0.0.0 tracker.net

# Plain domains
telemetry.service.io
*.wildcard-block.org
||adguard-rule.com^
`
	domains, err := ParseHosts(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error parsing hosts: %v", err)
	}

	expected := []string{
		"ads.example.com",
		"evil.com",
		"tracker.net",
		"telemetry.service.io",
		"*.wildcard-block.org",
		"adguard-rule.com",
	}

	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d] = true
	}

	for _, exp := range expected {
		if !domainMap[exp] {
			t.Errorf("expected domain %q to be parsed, but was not found in %v", exp, domains)
		}
	}

	// Localhost should NOT be in the parsed output
	if domainMap["localhost"] || domainMap["0.0.0.0"] || domainMap["ip6-localhost"] {
		t.Errorf("localhost entries should have been ignored, got %v", domains)
	}
}

func TestDomainTrieWildcard(t *testing.T) {
	trie := NewDomainTrie()

	trie.Insert("*.telemetry.google.com", true)
	trie.Insert("ads.yahoo.com", false)

	tests := []struct {
		domain string
		match  bool
	}{
		{"telemetry.google.com", true},
		{"sub.telemetry.google.com", true},
		{"deep.nested.telemetry.google.com", true},
		{"google.com", false},
		{"othergoogle.com", false},
		{"ads.yahoo.com", true},
		{"sub.ads.yahoo.com", false}, // exact match inserted, not wildcard
		{"yahoo.com", false},
	}

	for _, tc := range tests {
		got := trie.Matches(tc.domain)
		if got != tc.match {
			t.Errorf("Trie.Matches(%q) = %v, expected %v", tc.domain, got, tc.match)
		}
	}
}

func TestFilterEnginePrecedence(t *testing.T) {
	cfg := &config.BlockingConfig{
		Enabled:   true,
		BlockMode: "zero_ip",
		Blacklist: []string{
			"*.evil.com",
			"badtracker.com",
		},
		Whitelist: []string{
			"good.evil.com",
			"*.allowed.badtracker.com",
		},
		UpdateInterval: 10 * time.Minute,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(cfg, logger)

	if err := engine.LoadRules(context.Background()); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	tests := []struct {
		domain  string
		blocked bool
	}{
		{"evil.com", true},
		{"sub.evil.com", true},
		{"good.evil.com", false}, // Whitelist override
		{"badtracker.com", true},
		{"api.allowed.badtracker.com", false}, // Whitelist wildcard override
		{"google.com", false},
	}

	for _, tc := range tests {
		got := engine.IsBlocked(tc.domain)
		if got != tc.blocked {
			t.Errorf("IsBlocked(%q) = %v, expected %v", tc.domain, got, tc.blocked)
		}
	}
}

func BenchmarkFilter100kDomains(b *testing.B) {
	cfg := &config.BlockingConfig{
		Enabled:   true,
		BlockMode: "zero_ip",
		Blacklist: []string{"*.telemetry.tracking.org"},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(cfg, logger)

	snap := &FilterSnapshot{
		blacklistExact: make(map[string]struct{}, 100000),
		blacklistTrie:  NewDomainTrie(),
		whitelistExact: make(map[string]struct{}),
		whitelistTrie:  NewDomainTrie(),
	}

	for i := 0; i < 100000; i++ {
		d := fmt.Sprintf("ad-tracker-%d.evilcorp.com", i)
		snap.blacklistExact[d] = struct{}{}
	}
	snap.blacklistTrie.Insert("*.telemetry.tracking.org", true)
	snap.totalRules = 100001
	engine.snapshot.Store(snap)

	testDomains := []string{
		"ad-tracker-54321.evilcorp.com",
		"sub.telemetry.tracking.org",
		"google.com",
		"github.com",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, td := range testDomains {
			_ = engine.IsBlocked(td)
		}
	}
}
