package dns

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"tuxdnshole/internal/config"
)

type cacheKey struct {
	name   string
	qtype  uint16
	qclass uint16
}

type cacheEntry struct {
	key        cacheKey
	msg        *dns.Msg
	expireAt   time.Time
	initialTTL uint32
}

// Cache is a thread-safe, high-performance in-memory LRU cache for DNS responses with dynamic TTL adjustment.
type Cache struct {
	mu      sync.Mutex
	items   map[cacheKey]*list.Element
	evict   *list.List
	maxSize int
	minTTL  time.Duration
	maxTTL  time.Duration
	enabled bool
}

// NewCache initializes an LRU cache with the specified configuration.
func NewCache(cfg *config.CacheConfig) *Cache {
	if !cfg.Enabled || cfg.Size <= 0 {
		return &Cache{enabled: false}
	}

	minTTL := cfg.MinTTL
	if minTTL <= 0 {
		minTTL = 60 * time.Second
	}
	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = 86400 * time.Second
	}

	return &Cache{
		items:   make(map[cacheKey]*list.Element, cfg.Size),
		evict:   list.New(),
		maxSize: cfg.Size,
		minTTL:  minTTL,
		maxTTL:  maxTTL,
		enabled: true,
	}
}

// makeKey generates a normalized cacheKey for a given DNS question.
func makeKey(q dns.Question) cacheKey {
	return cacheKey{
		name:   strings.ToLower(dns.Fqdn(q.Name)),
		qtype:  q.Qtype,
		qclass: q.Qclass,
	}
}

// Get retrieves a response from the cache if available and not expired, adjusting remaining TTLs.
func (c *Cache) Get(req *dns.Msg) (*dns.Msg, bool) {
	if !c.enabled || req == nil || len(req.Question) == 0 {
		return nil, false
	}

	key := makeKey(req.Question[0])

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.items[key]
	if !exists {
		return nil, false
	}

	entry := elem.Value.(*cacheEntry)
	now := time.Now()

	// Check for TTL expiration
	if now.After(entry.expireAt) {
		c.evict.Remove(elem)
		delete(c.items, key)
		return nil, false
	}

	// Move to front of LRU list
	c.evict.MoveToFront(elem)

	// Calculate remaining TTL in seconds
	remainingTTL := uint32(entry.expireAt.Sub(now).Seconds())
	if remainingTTL == 0 {
		remainingTTL = 1
	}

	// Clone response to prevent mutation & assign original request ID
	cachedResp := entry.msg.Copy()
	cachedResp.Id = req.Id

	// Update TTLs across all sections
	updateRecordTTLs(cachedResp.Answer, remainingTTL)
	updateRecordTTLs(cachedResp.Ns, remainingTTL)
	updateRecordTTLs(cachedResp.Extra, remainingTTL)

	return cachedResp, true
}

// Set stores a DNS response in the cache with calculated TTL expiration.
func (c *Cache) Set(req *dns.Msg, resp *dns.Msg) {
	if !c.enabled || req == nil || resp == nil || len(req.Question) == 0 {
		return
	}

	// Do not cache server errors or truncated responses
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return
	}
	if resp.Truncated {
		return
	}

	ttl := calculateMinTTL(resp)
	if ttl == 0 {
		return
	}

	// Clamp TTL between min_ttl and max_ttl
	minSec := uint32(c.minTTL.Seconds())
	maxSec := uint32(c.maxTTL.Seconds())
	if ttl < minSec {
		ttl = minSec
	}
	if maxSec > 0 && ttl > maxSec {
		ttl = maxSec
	}

	key := makeKey(req.Question[0])
	expireAt := time.Now().Add(time.Duration(ttl) * time.Second)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already in cache
	if elem, exists := c.items[key]; exists {
		c.evict.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.msg = resp.Copy()
		entry.expireAt = expireAt
		entry.initialTTL = ttl
		return
	}

	// Evict oldest if full
	if c.evict.Len() >= c.maxSize {
		c.removeOldest()
	}

	entry := &cacheEntry{
		key:        key,
		msg:        resp.Copy(),
		expireAt:   expireAt,
		initialTTL: ttl,
	}
	elem := c.evict.PushFront(entry)
	c.items[key] = elem
}

func (c *Cache) removeOldest() {
	elem := c.evict.Back()
	if elem != nil {
		c.evict.Remove(elem)
		entry := elem.Value.(*cacheEntry)
		delete(c.items, entry.key)
	}
}

// Len returns current number of cached entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// calculateMinTTL finds the minimum TTL in the response records.
func calculateMinTTL(msg *dns.Msg) uint32 {
	var minTTL uint32 = 0
	found := false

	checkRecords := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if !found || h.Ttl < minTTL {
				minTTL = h.Ttl
				found = true
			}
		}
	}

	checkRecords(msg.Answer)
	checkRecords(msg.Ns)
	checkRecords(msg.Extra)

	if !found {
		// Default to 60s if no TTL found
		return 60
	}
	return minTTL
}

func updateRecordTTLs(rrs []dns.RR, ttl uint32) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype != dns.TypeOPT {
			h.Ttl = ttl
		}
	}
}
