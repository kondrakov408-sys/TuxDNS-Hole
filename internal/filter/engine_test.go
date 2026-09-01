package filter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
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

func TestRegexFiltering(t *testing.T) {
	cfg := &config.BlockingConfig{
		Enabled:   true,
		BlockMode: "zero_ip",
		RegexBlacklist: []string{
			`^telemetry\..*`,
			`.*-analytics\..*`,
		},
		Whitelist: []string{
			"telemetry.allowed-corp.com",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(cfg, logger)

	if err := engine.LoadRules(context.Background()); err != nil {
		t.Fatalf("failed to load regex rules: %v", err)
	}

	tests := []struct {
		domain  string
		blocked bool
	}{
		{"telemetry.windows.com", true},
		{"telemetry.sub.domain.org", true},
		{"app-analytics.company.io", true},
		{"telemetry.allowed-corp.com", false}, // Whitelist override
		{"google.com", false},
	}

	for _, tc := range tests {
		got := engine.IsBlocked(tc.domain)
		if got != tc.blocked {
			t.Errorf("Regex IsBlocked(%q) = %v, expected %v", tc.domain, got, tc.blocked)
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

func BenchmarkFilter1MillionDomains(b *testing.B) {
	cfg := &config.BlockingConfig{
		Enabled:   true,
		BlockMode: "zero_ip",
		Blacklist: []string{"*.telemetry.tracking.org"},
		RegexBlacklist: []string{
			`^adservice\..*`,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(cfg, logger)

	snap := &FilterSnapshot{
		blacklistExact: make(map[string]struct{}, 1000000),
		blacklistTrie:  NewDomainTrie(),
		whitelistExact: make(map[string]struct{}),
		whitelistTrie:  NewDomainTrie(),
	}

	// 1 Million domains in hash table + Trie
	for i := 0; i < 1000000; i++ {
		d := fmt.Sprintf("ad-tracker-%d.evilcorp%d.com", i, i%100)
		snap.blacklistExact[d] = struct{}{}
	}
	for i := 0; i < 5000; i++ {
		snap.blacklistTrie.Insert(fmt.Sprintf("*.tracking-network-%d.com", i), true)
	}
	snap.totalRules = 1005001
	engine.snapshot.Store(snap)

	testDomains := []string{
		"ad-tracker-543210.evilcorp10.com",     // Exact Match Hit
		"sub.deep.tracking-network-42.com",       // Trie Wildcard Hit
		"clean-news-site.org",                    // Miss
		"api.github.com",                         // Miss
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, td := range testDomains {
			_ = engine.IsBlocked(td)
		}
	}
}

func TestAtomicHotReloadNonBlocking(t *testing.T) {
	cfg := &config.BlockingConfig{
		Enabled:   true,
		BlockMode: "zero_ip",
		Blacklist: []string{"old-blocked.com"},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(cfg, logger)
	if err := engine.LoadRules(context.Background()); err != nil {
		t.Fatalf("failed to load initial rules: %v", err)
	}

	// Start continuous readers in background
	stopCh := make(chan struct{})
	var readCount uint64
	var readWg sync.WaitGroup

	for i := 0; i < 20; i++ {
		readWg.Add(1)
		go func() {
			defer readWg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					_ = engine.IsBlocked("old-blocked.com")
					_ = engine.IsBlocked("allowed-domain.org")
					atomic.AddUint64(&readCount, 2)
				}
			}
		}()
	}

	// Perform live reload while readers are bombarding the engine
	cfg.Blacklist = append(cfg.Blacklist, "newly-added-blocked.com")
	if err := engine.LoadRules(context.Background()); err != nil {
		t.Fatalf("failed to reload rules: %v", err)
	}

	// Verify newly added rule works immediately
	if !engine.IsBlocked("newly-added-blocked.com") {
		t.Errorf("expected newly added rule to be blocked after atomic swap")
	}

	close(stopCh)
	readWg.Wait()

	if readCount == 0 {
		t.Errorf("expected reads to occur during atomic reload")
	}
	t.Logf("Total non-blocking reads during reload: %d", readCount)
}


