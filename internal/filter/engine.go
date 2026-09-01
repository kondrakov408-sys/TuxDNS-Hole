package filter

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tuxdnshole/internal/config"
)

// TrieNode represents a memory-efficient node in the domain label suffix tree.
type TrieNode struct {
	children   map[string]*TrieNode
	isExact    bool
	isWildcard bool
}

func newTrieNode() *TrieNode {
	return &TrieNode{}
}

// DomainTrie efficiently stores and matches domain suffixes and wildcards with zero-allocation label traversal.
type DomainTrie struct {
	root  *TrieNode
	count int
	mu    sync.RWMutex
}

// NewDomainTrie initializes a new DomainTrie.
func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		root: newTrieNode(),
	}
}

// HasRules returns true if there are any patterns loaded in the Trie.
func (t *DomainTrie) HasRules() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count > 0
}

// Insert inserts a domain rule into the Trie.
// Wildcards (e.g. *.example.com) match all subdomains.
func (t *DomainTrie) Insert(domain string, isWildcard bool) {
	d := normalizeDomain(domain)
	if d == "" {
		return
	}

	if strings.HasPrefix(d, "*.") {
		d = strings.TrimPrefix(d, "*.")
		isWildcard = true
	} else if strings.HasPrefix(d, ".") {
		d = strings.TrimPrefix(d, ".")
		isWildcard = true
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	curr := t.root
	hasLabels := false

	// Traverse labels in reverse (e.g. "com", "example", "telemetry") without allocating string slices
	iterateDomainLabelsReverse(d, func(label string) bool {
		hasLabels = true
		if curr.children == nil {
			curr.children = make(map[string]*TrieNode, 2)
		}
		next, exists := curr.children[label]
		if !exists {
			next = newTrieNode()
			curr.children[label] = next
		}
		curr = next
		return true
	})

	if hasLabels {
		if isWildcard {
			curr.isWildcard = true
		} else {
			curr.isExact = true
		}
		t.count++
	}
}

// Matches checks whether the given domain matches any pattern in the Trie using zero-allocation reverse iteration.
func (t *DomainTrie) Matches(domain string) bool {
	if t.root == nil || t.count == 0 {
		return false
	}

	d := normalizeDomain(domain)
	if d == "" {
		return false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	curr := t.root
	allLabelsConsumed := true

	iterateDomainLabelsReverse(d, func(label string) bool {
		if curr.children == nil {
			allLabelsConsumed = false
			return false // stop iteration
		}

		next, exists := curr.children[label]
		if !exists {
			allLabelsConsumed = false
			return false // no further match
		}
		curr = next

		// If a wildcard was set on an ancestor node (e.g. *.google.com), all deeper subdomains match immediately
		if curr.isWildcard {
			return false // early stop, matched
		}

		return true
	})

	if curr.isWildcard {
		return true
	}

	return allLabelsConsumed && curr.isExact
}

// iterateDomainLabelsReverse scans domain labels from right to left without heap slice allocations.
func iterateDomainLabelsReverse(domain string, fn func(label string) bool) {
	end := len(domain)
	for end > 0 {
		idx := strings.LastIndexByte(domain[:end], '.')
		var label string
		if idx == -1 {
			label = domain[:end]
			end = 0
		} else {
			label = domain[idx+1 : end]
			end = idx
		}
		if label != "" {
			if !fn(label) {
				return
			}
		}
	}
}

// FilterSnapshot holds an immutable snapshot of loaded rules for atomic swapping.
type FilterSnapshot struct {
	blacklistExact map[string]struct{}
	blacklistTrie  *DomainTrie
	regexBlacklist []*regexp.Regexp
	whitelistExact map[string]struct{}
	whitelistTrie  *DomainTrie
	totalRules     int
}

// Engine manages domain filtering, blacklists, whitelists, and live reloads.
type Engine struct {
	cfg      *config.BlockingConfig
	logger   *slog.Logger
	snapshot atomic.Pointer[FilterSnapshot]
	reloadMu sync.Mutex
}

// NewEngine creates a new FilterEngine.
func NewEngine(cfg *config.BlockingConfig, logger *slog.Logger) *Engine {
	e := &Engine{
		cfg:    cfg,
		logger: logger,
	}

	// Initialize empty snapshot
	emptySnap := &FilterSnapshot{
		blacklistExact: make(map[string]struct{}),
		blacklistTrie:  NewDomainTrie(),
		whitelistExact: make(map[string]struct{}),
		whitelistTrie:  NewDomainTrie(),
	}
	e.snapshot.Store(emptySnap)
	return e
}

// LoadRules reloads all local and remote blocklists/whitelists and atomically swaps the rule snapshot.
func (e *Engine) LoadRules(ctx context.Context) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()

	if !e.cfg.Enabled {
		e.logger.Info("blocking is disabled by configuration")
		return nil
	}

	start := time.Now()
	newSnap := &FilterSnapshot{
		blacklistExact: make(map[string]struct{}, 128*1024),
		blacklistTrie:  NewDomainTrie(),
		whitelistExact: make(map[string]struct{}, 1024),
		whitelistTrie:  NewDomainTrie(),
	}

	// String interner to share string headers across overlapping blocklists and conserve heap RAM
	interner := make(map[string]string, 64*1024)
	intern := func(s string) string {
		if existing, ok := interner[s]; ok {
			return existing
		}
		interner[s] = s
		return s
	}

	// 1. Process Whitelist
	for _, raw := range e.cfg.Whitelist {
		clean := normalizeDomain(raw)
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "*.") || strings.HasPrefix(clean, ".") {
			newSnap.whitelistTrie.Insert(clean, true)
		} else {
			newSnap.whitelistExact[intern(clean)] = struct{}{}
		}
	}

	// 2. Process custom Blacklist
	for _, raw := range e.cfg.Blacklist {
		clean := normalizeDomain(raw)
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "*.") || strings.HasPrefix(clean, ".") {
			newSnap.blacklistTrie.Insert(clean, true)
		} else {
			newSnap.blacklistExact[intern(clean)] = struct{}{}
		}
	}

	// 3. Process Regex Blacklist
	for _, pattern := range e.cfg.RegexBlacklist {
		p := strings.TrimSpace(pattern)
		if p == "" {
			continue
		}
		compiled, err := regexp.Compile(p)
		if err != nil {
			e.logger.Warn("failed to compile blacklist regex", "pattern", p, "error", err)
			continue
		}
		newSnap.regexBlacklist = append(newSnap.regexBlacklist, compiled)
	}

	// 4. Process local blocklist files
	for _, path := range e.cfg.BlocklistFiles {
		domains, err := LoadFile(path)
		if err != nil {
			e.logger.Warn("failed to load local blocklist file", "file", path, "error", err)
			continue
		}
		for _, d := range domains {
			if strings.HasPrefix(d, "*.") || strings.HasPrefix(d, ".") {
				newSnap.blacklistTrie.Insert(d, true)
			} else {
				newSnap.blacklistExact[intern(d)] = struct{}{}
			}
		}
		e.logger.Debug("loaded local blocklist file", "file", path, "domains_count", len(domains))
	}

	// 5. Process remote blocklist URLs
	var wg sync.WaitGroup
	var urlMu sync.Mutex

	for _, rawURL := range e.cfg.BlocklistURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			fetchCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()

			domains, err := FetchURL(fetchCtx, url)
			if err != nil {
				e.logger.Warn("failed to fetch remote blocklist", "url", url, "error", err)
				return
			}

			urlMu.Lock()
			for _, d := range domains {
				if strings.HasPrefix(d, "*.") || strings.HasPrefix(d, ".") {
					newSnap.blacklistTrie.Insert(d, true)
				} else {
					newSnap.blacklistExact[intern(d)] = struct{}{}
				}
			}
			urlMu.Unlock()

			e.logger.Debug("fetched remote blocklist", "url", url, "domains_count", len(domains))
		}(rawURL)
	}

	wg.Wait()

	newSnap.totalRules = len(newSnap.blacklistExact) + newSnap.blacklistTrie.count + len(newSnap.regexBlacklist)
	e.snapshot.Store(newSnap)

	e.logger.Info("filter rules successfully updated",
		"total_blocked_domains", newSnap.totalRules,
		"regex_count", len(newSnap.regexBlacklist),
		"whitelist_count", len(e.cfg.Whitelist),
		"duration", time.Since(start).String(),
	)

	return nil
}

// IsBlocked checks if a domain should be sinkholed according to whitelist, blacklist, and regex rules.
func (e *Engine) IsBlocked(domain string) bool {
	if !e.cfg.Enabled {
		return false
	}

	snap := e.snapshot.Load()
	if snap == nil {
		return false
	}

	d := normalizeDomain(domain)
	if d == "" {
		return false
	}

	// 1. Fast path: check exact Whitelist match
	if _, ok := snap.whitelistExact[d]; ok {
		return false
	}

	// 2. Check Whitelist wildcard Trie (if rules exist)
	if snap.whitelistTrie.HasRules() && snap.whitelistTrie.Matches(d) {
		return false
	}

	// 3. Fast path: check exact Blacklist match
	if _, ok := snap.blacklistExact[d]; ok {
		return true
	}

	// 4. Check Blacklist wildcard Trie (if rules exist)
	if snap.blacklistTrie.HasRules() && snap.blacklistTrie.Matches(d) {
		return true
	}

	// 5. Check Regex patterns (only evaluated after exact and trie misses)
	for _, re := range snap.regexBlacklist {
		if re.MatchString(d) {
			return true
		}
	}

	return false
}

// TotalRules returns the total count of loaded blocking rules.
func (e *Engine) TotalRules() int {
	snap := e.snapshot.Load()
	if snap == nil {
		return 0
	}
	return snap.totalRules
}

// StartAutoUpdate runs a background goroutine to periodically refresh blocklists.
func (e *Engine) StartAutoUpdate(ctx context.Context) {
	if e.cfg.UpdateInterval <= 0 {
		return
	}

	ticker := time.NewTicker(e.cfg.UpdateInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.logger.Info("starting scheduled blocklist update...")
				if err := e.LoadRules(ctx); err != nil {
					e.logger.Error("scheduled blocklist update failed", "error", err)
				}
			}
		}
	}()
}
