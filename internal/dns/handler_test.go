package dns

import (
	"context"
	"io"
	"log/slog"
	"net"
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
