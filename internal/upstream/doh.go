package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// wellKnownBootstrapIPs provides fallback bootstrap IPs for known DoH providers to prevent cold-start deadlocks.
var wellKnownBootstrapIPs = map[string][]string{
	"dns.quad9.net": {
		"9.9.9.9",
		"149.112.112.112",
		"2620:fe::fe",
		"2620:fe::9",
	},
	"cloudflare-dns.com": {
		"1.1.1.1",
		"1.0.0.1",
		"2606:4700:4700::1111",
		"2606:4700:4700::1001",
	},
	"dns.mullvad.net": {
		"194.242.2.2",
		"194.242.2.3",
		"2a07:e340::2",
		"2a07:e340::3",
	},
	"dns.google": {
		"8.8.8.8",
		"8.8.4.4",
		"2001:4860:4860::8888",
		"2001:4860:4860::8844",
	},
	"dns.adguard-dns.com": {
		"94.140.14.14",
		"94.140.15.15",
		"2a10:50c0::ad1:ff",
		"2a10:50c0::ad2:ff",
	},
}

// DoHClient represents a DNS-over-HTTPS resolver client using HTTP/2 with direct bootstrap IP dialing.
type DoHClient struct {
	endpoint     string
	host         string
	port         string
	bootstrapIPs []string
	httpClient   *http.Client
	ipCounter    uint64
}

// NewDoHClient creates an optimized HTTP/2 DoH client with direct bootstrap IP dialing.
func NewDoHClient(
	endpoint string,
	timeout time.Duration,
	customBootstrapIPs []string,
	bootstrapMap map[string][]string,
) *DoHClient {
	parsedURL, err := url.Parse(endpoint)
	var host, port string
	if err == nil {
		host = parsedURL.Hostname()
		port = parsedURL.Port()
		if port == "" {
			if parsedURL.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
	}

	// Determine bootstrap IPs for this host
	var resolvedBootstraps []string

	// 1. Check if host is already an IP address
	if net.ParseIP(host) != nil {
		resolvedBootstraps = append(resolvedBootstraps, host)
	}

	// 2. Check explicit host mapping in config
	if bootstrapMap != nil {
		if ips, ok := bootstrapMap[host]; ok && len(ips) > 0 {
			resolvedBootstraps = append(resolvedBootstraps, ips...)
		}
	}

	// 3. Check well-known providers list
	if len(resolvedBootstraps) == 0 {
		if ips, ok := wellKnownBootstrapIPs[strings.ToLower(host)]; ok && len(ips) > 0 {
			resolvedBootstraps = append(resolvedBootstraps, ips...)
		}
	}

	// 4. Append general bootstrap IPs if supplied
	if len(customBootstrapIPs) > 0 {
		resolvedBootstraps = append(resolvedBootstraps, customBootstrapIPs...)
	}

	client := &DoHClient{
		endpoint:     endpoint,
		host:         host,
		port:         port,
		bootstrapIPs: resolvedBootstraps,
	}

	// Custom DialContext bypassing system DNS lookups for DoH host to prevent cold-start deadlock
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		reqHost, reqPort, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			reqHost = addr
			reqPort = port
		}

		// If connecting to the DoH server host and we have bootstrap IPs, dial them directly
		if strings.EqualFold(reqHost, host) && len(client.bootstrapIPs) > 0 {
			n := len(client.bootstrapIPs)
			startIdx := int(atomic.AddUint64(&client.ipCounter, 1) % uint64(n))

			var lastErr error
			for i := 0; i < n; i++ {
				targetIP := client.bootstrapIPs[(startIdx+i)%n]
				targetAddr := net.JoinHostPort(targetIP, reqPort)

				conn, err := dialer.DialContext(ctx, network, targetAddr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("bootstrap direct dial failed for %s (%w)", host, lastErr)
		}

		// Fallback to standard network dialer
		return dialer.DialContext(ctx, network, addr)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName: host, // Ensure TLS SNI matches provider hostname even when connecting to IP directly
			MinVersion: tls.VersionTLS12,
		},
	}

	client.httpClient = &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return client
}

// Exchange sends a DNS wire message to the DoH endpoint via HTTP POST and parses the DNS response.
func (c *DoHClient) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// Pack DNS message to wire format
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns query: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "TuxDNS-Hole/1.0 (+https://github.com/tuxdns/tuxdnshole)")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh http post error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh server returned http status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read doh response body: %w", err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack doh response wire format: %w", err)
	}

	// RFC 8484 Section 4.2.1: In DoH, ID is often set to 0. Restore original request ID.
	respMsg.Id = req.Id

	return respMsg, nil
}
