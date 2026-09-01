package upstream

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tuxdnshole/internal/config"
)

func startMockDNSServer(t *testing.T) (*dns.Server, string) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp packet conn: %v", err)
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			if q.Qtype == dns.TypeA {
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("1.2.3.4"),
					},
				}
			}
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	return server, pc.LocalAddr().String()
}

func TestForwarderStandardUDP(t *testing.T) {
	mockServer, addr := startMockDNSServer(t)
	defer mockServer.Shutdown()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.UpstreamConfig{
		Servers:  []string{addr},
		Timeout:  2 * time.Second,
		Strategy: "round_robin",
	}

	f, err := NewForwarder(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create forwarder: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("test.example.com.", dns.TypeA)

	resp, rtt, err := f.Forward(context.Background(), req)
	if err != nil {
		t.Fatalf("forward failed: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %v", resp)
	}
	t.Logf("DNS response received in %v: %v", rtt, resp.Answer[0])
}

func TestForwarderFailoverOnDeadUpstream(t *testing.T) {
	// Server 2 is healthy, Server 1 is dead
	mockServer2, addr2 := startMockDNSServer(t)
	defer mockServer2.Shutdown()

	deadAddr := "127.0.0.1:58888" // Closed port

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.UpstreamConfig{
		Servers:  []string{deadAddr, addr2},
		Timeout:  100 * time.Millisecond,
		Strategy: "failover",
	}

	f, err := NewForwarder(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create forwarder: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("failover.test.com.", dns.TypeA)

	resp, _, err := f.Forward(context.Background(), req)
	if err != nil {
		t.Fatalf("expected failover to succeed, got error: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected response from healthy backup server, got %v", resp)
	}
}

func TestForwarderAllUpstreamsFailNoPanic(t *testing.T) {
	deadAddr1 := "127.0.0.1:58888"
	deadAddr2 := "127.0.0.1:58889"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.UpstreamConfig{
		Servers:  []string{deadAddr1, deadAddr2},
		Timeout:  50 * time.Millisecond,
		Strategy: "round_robin",
	}

	f, err := NewForwarder(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create forwarder: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	// Must return error without panic
	resp, _, err := f.Forward(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error when all upstreams are dead, got nil")
	}
	if resp != nil {
		t.Errorf("expected nil response on error, got %v", resp)
	}
}

func TestForwarderParallel(t *testing.T) {
	mockServer, healthyAddr := startMockDNSServer(t)
	defer mockServer.Shutdown()

	deadAddr := "127.0.0.1:58888"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.UpstreamConfig{
		Servers:  []string{deadAddr, healthyAddr},
		Timeout:  500 * time.Millisecond,
		Strategy: "parallel",
	}

	f, err := NewForwarder(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create forwarder: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("parallel.test.com.", dns.TypeA)

	resp, _, err := f.Forward(context.Background(), req)
	if err != nil {
		t.Fatalf("expected parallel forward to succeed via healthy server: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer from parallel query, got %v", resp)
	}
}

