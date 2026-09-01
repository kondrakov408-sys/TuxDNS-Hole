package dns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tuxdnshole/internal/config"
	"tuxdnshole/internal/filter"
	"tuxdnshole/internal/upstream"
)

type mockResponseWriter struct {
	msg *dns.Msg
}

func (m *mockResponseWriter) LocalAddr() net.Addr       { return nil }
func (m *mockResponseWriter) RemoteAddr() net.Addr      { return nil }
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) Close() error               { return nil }
func (m *mockResponseWriter) TsigStatus() error         { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)       {}
func (m *mockResponseWriter) Hijack()                   {}

func startMockCNAMEUpstream(t *testing.T) (*dns.Server, string) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			if q.Name == "metrics.legit-site.com." {
				// CNAME cloaking: disguised tracker
				m.Answer = []dns.RR{
					&dns.CNAME{
						Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
						Target: "tracker.thirdparty-analytics.com.",
					},
					&dns.A{
						Hdr: dns.RR_Header{Name: "tracker.thirdparty-analytics.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("198.51.100.1"),
					},
				}
			} else {
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("93.184.216.34"),
					},
				}
			}
		}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return srv, pc.LocalAddr().String()
}

func TestCNAMEUncloaking(t *testing.T) {
	mockSrv, mockAddr := startMockCNAMEUpstream(t)
	defer mockSrv.Shutdown()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenAddrs: []string{"127.0.0.1:1053"},
			DNSSEC:      false,
		},
		Upstream: config.UpstreamConfig{
			Servers:  []string{mockAddr},
			Timeout:  2 * time.Second,
			Strategy: "round_robin",
		},
		Blocking: config.BlockingConfig{
			Enabled:         true,
			BlockMode:       "zero_ip",
			Blacklist:       []string{"tracker.thirdparty-analytics.com"},
			CNAMEUncloaking: true,
			CustomZeroIPv4:  "0.0.0.0",
			TTL:             300,
		},
		Cache: config.CacheConfig{Enabled: false},
	}

	filterEngine := filter.NewEngine(&cfg.Blocking, logger)
	if err := filterEngine.LoadRules(context.Background()); err != nil {
		t.Fatalf("failed to load filter rules: %v", err)
	}

	forwarder, err := upstream.NewForwarder(&cfg.Upstream, logger)
	if err != nil {
		t.Fatalf("failed to create forwarder: %v", err)
	}

	cache := NewCache(&cfg.Cache)
	handler := NewHandler(cfg, filterEngine, forwarder, cache, logger)

	// 1. Query disguised domain: "metrics.legit-site.com."
	req := new(dns.Msg)
	req.SetQuestion("metrics.legit-site.com.", dns.TypeA)

	w := &mockResponseWriter{}
	handler.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatalf("expected response message, got nil")
	}

	// Should be sinkholed to 0.0.0.0 because its CNAME target tracker.thirdparty-analytics.com is in blacklist!
	if len(w.msg.Answer) == 0 {
		t.Fatalf("expected sinkhole answer, got 0 records")
	}

	aRecord, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", w.msg.Answer[0])
	}

	if aRecord.A.String() != "0.0.0.0" {
		t.Errorf("expected cloaked CNAME to be sinkholed to 0.0.0.0, got %s", aRecord.A.String())
	}
}

func TestHandlerCacheLatency(t *testing.T) {
	mockSrv, mockAddr := startMockCNAMEUpstream(t)
	defer mockSrv.Shutdown()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Server: config.ServerConfig{DNSSEC: false},
		Upstream: config.UpstreamConfig{
			Servers:  []string{mockAddr},
			Timeout:  2 * time.Second,
			Strategy: "round_robin",
		},
		Blocking: config.BlockingConfig{Enabled: false},
		Cache:    config.CacheConfig{Enabled: true, Size: 1000, MinTTL: 60 * time.Second, MaxTTL: 3600 * time.Second},
	}

	filterEngine := filter.NewEngine(&cfg.Blocking, logger)
	forwarder, _ := upstream.NewForwarder(&cfg.Upstream, logger)
	cache := NewCache(&cfg.Cache)
	handler := NewHandler(cfg, filterEngine, forwarder, cache, logger)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	// First query (cold cache, forwarded)
	w1 := &mockResponseWriter{}
	handler.ServeDNS(w1, req)

	// Second query (cached) - measure latency
	w2 := &mockResponseWriter{}
	start := time.Now()
	handler.ServeDNS(w2, req)
	duration := time.Since(start)

	if duration > 1*time.Millisecond {
		t.Errorf("expected cache response < 1ms, got %v", duration)
	}
	t.Logf("Cached DNS Query Latency: %v (< 1ms requirement satisfied)", duration)
}

func TestHandlerUpstreamFailureGraceful(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Point to dead upstream port
	cfg := &config.Config{
		Server: config.ServerConfig{DNSSEC: false},
		Upstream: config.UpstreamConfig{
			Servers:  []string{"127.0.0.1:59999"},
			Timeout:  50 * time.Millisecond,
			Strategy: "round_robin",
		},
		Blocking: config.BlockingConfig{Enabled: false},
		Cache:    config.CacheConfig{Enabled: false},
	}

	filterEngine := filter.NewEngine(&cfg.Blocking, logger)
	forwarder, _ := upstream.NewForwarder(&cfg.Upstream, logger)
	cache := NewCache(&cfg.Cache)
	handler := NewHandler(cfg, filterEngine, forwarder, cache, logger)

	req := new(dns.Msg)
	req.SetQuestion("nonexistent.com.", dns.TypeA)
	req.Id = 9999

	w := &mockResponseWriter{}
	// Must not panic, must return SERVFAIL
	handler.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatalf("expected SERVFAIL response, got nil")
	}
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected RcodeServerFailure (SERVFAIL), got %d", w.msg.Rcode)
	}
}

func TestHandlerGoroutinesAndRace(t *testing.T) {
	mockSrv, mockAddr := startMockCNAMEUpstream(t)
	defer mockSrv.Shutdown()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Server: config.ServerConfig{DNSSEC: false},
		Upstream: config.UpstreamConfig{
			Servers:  []string{mockAddr},
			Timeout:  1 * time.Second,
			Strategy: "round_robin",
		},
		Blocking: config.BlockingConfig{Enabled: true, Blacklist: []string{"blocked.com"}, CustomZeroIPv4: "0.0.0.0"},
		Cache:    config.CacheConfig{Enabled: true, Size: 1000, MinTTL: 60 * time.Second, MaxTTL: 3600 * time.Second},
	}

	filterEngine := filter.NewEngine(&cfg.Blocking, logger)
	_ = filterEngine.LoadRules(context.Background())
	forwarder, _ := upstream.NewForwarder(&cfg.Upstream, logger)
	cache := NewCache(&cfg.Cache)
	handler := NewHandler(cfg, filterEngine, forwarder, cache, logger)

	// Send 200 concurrent queries
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := new(dns.Msg)
			if idx%3 == 0 {
				req.SetQuestion("blocked.com.", dns.TypeA)
			} else {
				req.SetQuestion("example.com.", dns.TypeA)
			}
			req.Id = uint16(idx)
			w := &mockResponseWriter{}
			handler.ServeDNS(w, req)
		}(i)
	}
	wg.Wait()
}

func TestEDNSClientSubnetStripping(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Server: config.ServerConfig{DNSSEC: true},
	}
	handler := NewHandler(cfg, nil, nil, nil, logger)

	// Create DNS request with EDNS Client Subnet (ECS, RFC 7871)
	req := new(dns.Msg)
	req.SetQuestion("privacy-test.com.", dns.TypeA)

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)

	// Attach ECS option containing client IP subnet (e.g. 198.51.100.0/24)
	ecsOption := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1, // IPv4
		SourceNetmask: 24,
		SourceScope:   0,
		Address:       net.ParseIP("198.51.100.0").To4(),
	}
	opt.Option = append(opt.Option, ecsOption)
	req.Extra = append(req.Extra, opt)

	// Verify original request has ECS
	if req.IsEdns0() == nil || len(req.IsEdns0().Option) == 0 {
		t.Fatalf("failed to setup test ECS option in request")
	}

	// Prepare upstream query
	prepared := handler.prepareUpstreamQuery(req)

	// Ensure ECS option was completely stripped
	preparedOpt := prepared.IsEdns0()
	if preparedOpt != nil {
		for _, o := range preparedOpt.Option {
			if o.Option() == dns.EDNS0SUBNET {
				t.Fatalf("ECS (EDNS0 Client Subnet) was NOT stripped from upstream query!")
			}
		}
		// Verify DNSSEC DO bit is still preserved/set
		if !preparedOpt.Do() {
			t.Errorf("expected DNSSEC DO bit to be enabled")
		}
	}
}

func startMockRebindingUpstream(t *testing.T) (*dns.Server, string) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			qname := strings.ToLower(q.Name)
			if qname == "attacker.com." {
				// Rebinding attack: resolves to loopback
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("127.0.0.1"),
					},
				}
			} else if qname == "router.lan." {
				// Legitimate local router address
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("192.168.1.1"),
					},
				}
			} else {
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("93.184.216.34"),
					},
				}
			}
		}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return srv, pc.LocalAddr().String()
}

func TestDNSRebindingProtection(t *testing.T) {
	mockSrv, mockAddr := startMockRebindingUpstream(t)
	defer mockSrv.Shutdown()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Server: config.ServerConfig{DNSSEC: false},
		Upstream: config.UpstreamConfig{
			Servers:  []string{mockAddr},
			Timeout:  2 * time.Second,
			Strategy: "round_robin",
		},
		Blocking: config.BlockingConfig{
			Enabled:        true,
			BlockMode:      "zero_ip",
			CustomZeroIPv4: "0.0.0.0",
		},
		Cache: config.CacheConfig{Enabled: false},
		OpSec: config.OpSecConfig{
			DNSRebindingProtection: true,
			AllowedLocalDomains:    []string{"*.local", "*.lan", "localhost"},
		},
	}

	filterEngine := filter.NewEngine(&cfg.Blocking, logger)
	forwarder, err := upstream.NewForwarder(&cfg.Upstream, logger)
	if err != nil {
		t.Fatalf("failed to create forwarder: %v", err)
	}

	cache := NewCache(&cfg.Cache)
	handler := NewHandler(cfg, filterEngine, forwarder, cache, logger)

	// 1. Query malicious public domain "attacker.com" resolving to 127.0.0.1
	req1 := new(dns.Msg)
	req1.SetQuestion("attacker.com.", dns.TypeA)
	w1 := &mockResponseWriter{}
	handler.ServeDNS(w1, req1)

	if w1.msg == nil || len(w1.msg.Answer) == 0 {
		t.Fatalf("expected sinkholed response for rebinding query, got nil")
	}

	aRecord1, ok := w1.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", w1.msg.Answer[0])
	}
	if aRecord1.A.IsLoopback() {
		t.Fatal("SECURITY LEAK: Upstream loopback IP was not filtered out by rebinding protection!")
	}
	if aRecord1.A.String() != "0.0.0.0" {
		t.Errorf("expected rebinding domain to be sinkholed to 0.0.0.0, got %s", aRecord1.A.String())
	}

	// 2. Query legitimate local domain "router.lan" resolving to 192.168.1.1
	req2 := new(dns.Msg)
	req2.SetQuestion("router.lan.", dns.TypeA)
	w2 := &mockResponseWriter{}
	handler.ServeDNS(w2, req2)

	if w2.msg == nil || len(w2.msg.Answer) == 0 {
		t.Fatalf("expected response for local domain, got nil")
	}

	aRecord2, ok := w2.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record for local domain, got %T", w2.msg.Answer[0])
	}
	if aRecord2.A.String() != "192.168.1.1" {
		t.Errorf("expected allowed local domain router.lan to resolve to 192.168.1.1, got %s", aRecord2.A.String())
	}
}

func TestEDNS0PaddingBlockAlignment(t *testing.T) {
	testDomains := []string{
		"a.com.",
		"short.com.",
		"medium-length-test-domain.privacy.org.",
		"very.long.subdomain.with.many.deep.nested.labels.example.com.",
	}

	for _, domain := range testDomains {
		req := new(dns.Msg)
		req.SetQuestion(domain, dns.TypeA)

		ApplyEDNS0Padding(req, 128)

		opt := req.IsEdns0()
		if opt == nil {
			t.Fatalf("EDNS0 OPT RR missing for domain %s", domain)
		}

		wireLen := req.Len()
		if wireLen%128 != 0 {
			t.Fatalf("Domain %s: Expected wire size multiple of 128, got %d bytes (rem: %d)", domain, wireLen, wireLen%128)
		}
	}
}

func TestDNS0x20CaseRandomization(t *testing.T) {
	domain := "google.com."
	randomized := Randomize0x20(domain)

	if strings.ToLower(randomized) != domain {
		t.Errorf("Randomize0x20 changed domain name value: %s -> %s", domain, randomized)
	}

	// Verify case-matching function
	if !Is0x20Match(randomized, randomized) {
		t.Errorf("expected exact 0x20 match to return true")
	}
	if Is0x20Match("gOoGlE.com.", "google.com.") {
		t.Errorf("expected mismatched casing to return false")
	}
}

func TestZeroDiskRingBuffer(t *testing.T) {
	rb := NewRingBuffer(5)

	if rb.Len() != 5 {
		t.Fatalf("expected ring buffer len 5, got %d", rb.Len())
	}

	// Push 7 items to verify circular overwrite in RAM
	for i := 0; i < 7; i++ {
		rb.Push(&QueryLogEntry{
			Timestamp: time.Now(),
			Domain:    fmt.Sprintf("domain-%d.com", i),
			Qtype:     dns.TypeA,
			Status:    "forwarded",
			RTT:       100 * time.Microsecond,
		})
	}

	recent := rb.GetRecent(5)
	if len(recent) != 5 {
		t.Fatalf("expected 5 recent entries, got %d", len(recent))
	}

	// Latest pushed domain was domain-6.com
	if recent[0].Domain != "domain-6.com" {
		t.Errorf("expected most recent entry to be domain-6.com, got %s", recent[0].Domain)
	}
}

func BenchmarkMemoryLeakSoakTest(b *testing.B) {
	mockSrv, mockAddr := startMockCNAMEUpstream(nil)
	defer mockSrv.Shutdown()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Server: config.ServerConfig{DNSSEC: false},
		Upstream: config.UpstreamConfig{
			Servers:  []string{mockAddr},
			Timeout:  1 * time.Second,
			Strategy: "round_robin",
		},
		Blocking: config.BlockingConfig{Enabled: false},
		Cache:    config.CacheConfig{Enabled: true, Size: 10000, MinTTL: 60 * time.Second, MaxTTL: 3600 * time.Second},
		OpSec: config.OpSecConfig{
			EDNS0Padding:           true,
			PaddingBlockSize:       128,
			DNSRebindingProtection: true,
			DNS0x20:                true,
			RingBufferSize:         1000,
		},
	}

	filterEngine := filter.NewEngine(&cfg.Blocking, logger)
	forwarder, _ := upstream.NewForwarder(&cfg.Upstream, logger)
	cache := NewCache(&cfg.Cache)
	handler := NewHandler(cfg, filterEngine, forwarder, cache, logger)

	req := new(dns.Msg)
	req.SetQuestion("bench.privacy.org.", dns.TypeA)

	// Pre-populate cache
	wInit := &mockResponseWriter{}
	handler.ServeDNS(wInit, req)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := &mockResponseWriter{}
			handler.ServeDNS(w, req)
		}
	})
}



