package dns

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"tuxdnshole/internal/config"
	"tuxdnshole/internal/filter"
	"tuxdnshole/internal/upstream"
)

// Handler implements dns.Handler to process incoming client DNS queries.
type Handler struct {
	cfg       *config.Config
	filter    *filter.Engine
	forwarder *upstream.Forwarder
	cache     *Cache
	logger    *slog.Logger
	zeroIPv4  net.IP
	zeroIPv6  net.IP
}

// NewHandler creates a new DNS query Handler.
func NewHandler(
	cfg *config.Config,
	filterEngine *filter.Engine,
	forwarder *upstream.Forwarder,
	cache *Cache,
	logger *slog.Logger,
) *Handler {
	zeroIPv4 := net.ParseIP(cfg.Blocking.CustomZeroIPv4)
	if zeroIPv4 == nil {
		zeroIPv4 = net.IPv4zero
	}
	zeroIPv6 := net.ParseIP(cfg.Blocking.CustomZeroIPv6)
	if zeroIPv6 == nil {
		zeroIPv6 = net.IPv6zero
	}

	return &Handler{
		cfg:       cfg,
		filter:    filterEngine,
		forwarder: forwarder,
		cache:     cache,
		logger:    logger,
		zeroIPv4:  zeroIPv4,
		zeroIPv6:  zeroIPv6,
	}
}

// ServeDNS handles incoming UDP and TCP DNS requests.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(dns.Fqdn(q.Name))

	// 1. Check if domain is blocked by the filter engine
	if h.filter.IsBlocked(qname) {
		h.handleBlocked(w, r, q, qname)
		return
	}

	// 2. Check LRU Cache for clean queries
	if cachedResp, hit := h.cache.Get(r); hit {
		h.logQuery("cache_hit", qname, q.Qtype, 0)
		_ = w.WriteMsg(cachedResp)
		return
	}

	// 3. Forward to Upstream Resolvers
	ctx, cancel := context.WithTimeout(context.Background(), h.cfg.Upstream.Timeout+1*time.Second)
	defer cancel()

	resp, rtt, err := h.forwarder.Forward(ctx, r)
	if err != nil {
		h.logger.Warn("upstream resolution failed", "domain", qname, "type", dns.TypeToString[q.Qtype], "error", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	// 4. Save to Cache and reply to client
	h.cache.Set(r, resp)
	h.logQuery("forwarded", qname, q.Qtype, rtt)
	_ = w.WriteMsg(resp)
}

// handleBlocked generates and sends a sinkhole response.
func (h *Handler) handleBlocked(w dns.ResponseWriter, r *dns.Msg, q dns.Question, domain string) {
	h.logQuery("blocked", domain, q.Qtype, 0)

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true
	resp.RecursionAvailable = true

	ttl := h.cfg.Blocking.TTL
	if ttl == 0 {
		ttl = 300
	}

	if h.cfg.Blocking.BlockMode == "nxdomain" {
		resp.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(resp)
		return
	}

	// zero_ip block mode
	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				A: h.zeroIPv4,
			},
		}
	case dns.TypeAAAA:
		resp.Answer = []dns.RR{
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				AAAA: h.zeroIPv6,
			},
		}
	default:
		// For other types (e.g. HTTPS, TXT, MX), return NOERROR with empty answer (NODATA)
		resp.Rcode = dns.RcodeSuccess
	}

	_ = w.WriteMsg(resp)
}

// logQuery handles structured logging while strictly respecting OpSec Zero-Log rules.
func (h *Handler) logQuery(status string, domain string, qtype uint16, rtt time.Duration) {
	if h.cfg.OpSec.ZeroLog {
		// Zero-Log Mode: Only log blocked events if debug logging is specifically active
		if status == "blocked" {
			h.logger.Debug("sinkholed domain query", "domain", domain, "type", dns.TypeToString[qtype], "action", "blocked")
		}
		return
	}

	// Non-Zero-Log Mode (if user explicitly enabled logging):
	h.logger.Debug("dns query processed",
		"status", status,
		"domain", domain,
		"type", dns.TypeToString[qtype],
		"rtt", rtt.String(),
	)
}
