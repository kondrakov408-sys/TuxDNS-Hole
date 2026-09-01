package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tuxdnshole/internal/config"
)

func TestDNSCache(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled: true,
		Size:    2,
		MinTTL:  2 * time.Second,
		MaxTTL:  10 * time.Second,
	}
	cache := NewCache(cfg)

	req1 := new(dns.Msg)
	req1.SetQuestion("example.com.", dns.TypeA)
	req1.Id = 1234

	resp1 := new(dns.Msg)
	resp1.SetReply(req1)
	resp1.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    5,
			},
			A: net.ParseIP("93.184.216.34"),
		},
	}

	// 1. Store in cache
	cache.Set(req1, resp1)
	if cache.Len() != 1 {
		t.Fatalf("expected cache len 1, got %d", cache.Len())
	}

	// 2. Query with different request ID
	req1Diff := new(dns.Msg)
	req1Diff.SetQuestion("example.com.", dns.TypeA)
	req1Diff.Id = 5678

	cached, hit := cache.Get(req1Diff)
	if !hit {
		t.Fatalf("expected cache hit for example.com")
	}
	if cached.Id != 5678 {
		t.Errorf("expected cached response ID to match req ID 5678, got %d", cached.Id)
	}
	if len(cached.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(cached.Answer))
	}

	// 3. Test LRU eviction when exceeding size 2
	req2 := new(dns.Msg)
	req2.SetQuestion("two.com.", dns.TypeA)
	resp2 := new(dns.Msg)
	resp2.SetReply(req2)
	resp2.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "two.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
			A:   net.ParseIP("1.1.1.1"),
		},
	}
	cache.Set(req2, resp2)

	// Access req1 to make req2 the oldest
	_, _ = cache.Get(req1)

	// Add 3rd item
	req3 := new(dns.Msg)
	req3.SetQuestion("three.com.", dns.TypeA)
	resp3 := new(dns.Msg)
	resp3.SetReply(req3)
	resp3.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "three.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
			A:   net.ParseIP("2.2.2.2"),
		},
	}
	cache.Set(req3, resp3)

	// req2 should have been evicted, req1 and req3 should still be in cache
	if _, hit := cache.Get(req2); hit {
		t.Errorf("expected req2 to be evicted from cache")
	}
	if _, hit := cache.Get(req1); !hit {
		t.Errorf("expected req1 to remain in cache")
	}
	if _, hit := cache.Get(req3); !hit {
		t.Errorf("expected req3 to remain in cache")
	}
}

func TestDNSCacheConcurrencyRace(t *testing.T) {
	cfg := &config.CacheConfig{
		Enabled: true,
		Size:    1000,
		MinTTL:  10 * time.Second,
		MaxTTL:  60 * time.Second,
	}
	c := NewCache(cfg)

	done := make(chan bool)
	for i := 0; i < 50; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				req := new(dns.Msg)
				req.SetQuestion(net.JoinHostPort("domain", "com."), dns.TypeA)
				req.Id = uint16(id*100 + j)

				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "domain.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("1.1.1.1"),
					},
				}

				c.Set(req, resp)
				_, _ = c.Get(req)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}

func BenchmarkCacheGet(b *testing.B) {
	cfg := &config.CacheConfig{
		Enabled: true,
		Size:    10000,
		MinTTL:  60 * time.Second,
		MaxTTL:  3600 * time.Second,
	}
	c := NewCache(cfg)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Id = 1234

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		},
	}
	c.Set(req, resp)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = c.Get(req)
	}
}


