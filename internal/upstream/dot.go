package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DoTClient represents a DNS-over-TLS resolver client (RFC 7858) with bootstrap resolution.
type DoTClient struct {
	endpoint     string
	host         string
	port         string
	bootstrapIPs []string
	dnsClient    *dns.Client
	tlsConfig    *tls.Config
	ipCounter    uint64
	timeout      time.Duration
}

// NewDoTClient creates an optimized DNS-over-TLS client.
func NewDoTClient(
	endpoint string,
	timeout time.Duration,
	customBootstrapIPs []string,
	bootstrapMap map[string][]string,
) *DoTClient {
	raw := endpoint
	if strings.HasPrefix(raw, "tls://") {
		raw = strings.TrimPrefix(raw, "tls://")
	}

	var host, port string
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil {
			host = u.Hostname()
			port = u.Port()
		}
	} else {
		var err error
		host, port, err = net.SplitHostPort(raw)
		if err != nil {
			host = raw
			port = "853"
		}
	}

	if port == "" {
		port = "853"
	}

	var resolvedBootstraps []string

	if net.ParseIP(host) != nil {
		resolvedBootstraps = append(resolvedBootstraps, host)
	}

	if bootstrapMap != nil {
		if ips, ok := bootstrapMap[host]; ok && len(ips) > 0 {
			resolvedBootstraps = append(resolvedBootstraps, ips...)
		}
	}

	if len(resolvedBootstraps) == 0 {
		if ips, ok := wellKnownBootstrapIPs[strings.ToLower(host)]; ok && len(ips) > 0 {
			resolvedBootstraps = append(resolvedBootstraps, ips...)
		}
	}

	if len(customBootstrapIPs) > 0 {
		resolvedBootstraps = append(resolvedBootstraps, customBootstrapIPs...)
	}

	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	dnsClient := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Timeout:   timeout,
	}

	return &DoTClient{
		endpoint:     endpoint,
		host:         host,
		port:         port,
		bootstrapIPs: resolvedBootstraps,
		dnsClient:    dnsClient,
		tlsConfig:    tlsConfig,
		timeout:      timeout,
	}
}

// Address returns the endpoint address.
func (c *DoTClient) Address() string {
	return c.endpoint
}

// Exchange performs a DNS-over-TLS query.
func (c *DoTClient) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(c.bootstrapIPs) > 0 {
		n := len(c.bootstrapIPs)
		startIdx := int(atomic.AddUint64(&c.ipCounter, 1) % uint64(n))

		var lastErr error
		for i := 0; i < n; i++ {
			targetIP := c.bootstrapIPs[(startIdx+i)%n]
			targetAddr := net.JoinHostPort(targetIP, c.port)

			resp, _, err := c.dnsClient.ExchangeContext(ctx, req, targetAddr)
			if err == nil && resp != nil {
				resp.Id = req.Id
				return resp, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("dot bootstrap query failed for %s (%w)", c.host, lastErr)
	}

	targetAddr := net.JoinHostPort(c.host, c.port)
	resp, _, err := c.dnsClient.ExchangeContext(ctx, req, targetAddr)
	if err != nil {
		return nil, fmt.Errorf("dot query failed (%s): %w", targetAddr, err)
	}

	if resp != nil {
		resp.Id = req.Id
	}
	return resp, nil
}
