package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"tuxdnshole/internal/config"
)

// UpstreamResolver represents an interface to query a single upstream DNS server.
type UpstreamResolver interface {
	Address() string
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// StandardResolver handles standard UDP/TCP DNS queries.
type StandardResolver struct {
	address   string
	udpClient *dns.Client
	tcpClient *dns.Client
	timeout   time.Duration
}

// NewStandardResolver creates a new standard UDP/TCP DNS resolver.
func NewStandardResolver(addr string, timeout time.Duration) *StandardResolver {
	// If no port is specified, default to 53
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}

	return &StandardResolver{
		address: addr,
		udpClient: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

func (r *StandardResolver) Address() string {
	return r.address
}

func (r *StandardResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// 1. Try UDP first
	resp, _, err := r.udpClient.ExchangeContext(ctx, req, r.address)
	if err == nil {
		// If response was truncated, fallback to TCP
		if resp != nil && resp.Truncated {
			respTCP, _, errTCP := r.tcpClient.ExchangeContext(ctx, req, r.address)
			if errTCP == nil {
				return respTCP, nil
			}
		}
		return resp, nil
	}

	// 2. Try TCP on network error
	resp, _, err = r.tcpClient.ExchangeContext(ctx, req, r.address)
	if err != nil {
		return nil, fmt.Errorf("standard dns error (%s): %w", r.address, err)
	}
	return resp, nil
}

// DoHResolver wraps DoHClient to implement UpstreamResolver.
type DoHResolver struct {
	endpoint string
	client   *DoHClient
}

func NewDoHResolver(endpoint string, timeout time.Duration, bootstrapIPs []string, bootstrapMap map[string][]string) *DoHResolver {
	return &DoHResolver{
		endpoint: endpoint,
		client:   NewDoHClient(endpoint, timeout, bootstrapIPs, bootstrapMap),
	}
}

func (r *DoHResolver) Address() string {
	return r.endpoint
}

func (r *DoHResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.client.Exchange(ctx, req)
}

// Forwarder manages an upstream resolver pool with load balancing and failover.
type Forwarder struct {
	resolvers []UpstreamResolver
	strategy  string
	timeout   time.Duration
	counter   uint64
	logger    *slog.Logger
}

// NewForwarder creates a Forwarder pool from UpstreamConfig.
func NewForwarder(cfg *config.UpstreamConfig, logger *slog.Logger) (*Forwarder, error) {
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("no upstream servers configured")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	var resolvers []UpstreamResolver
	for _, server := range cfg.Servers {
		s := strings.TrimSpace(server)
		if s == "" {
			continue
		}

		if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
			resolvers = append(resolvers, NewDoHResolver(s, timeout, cfg.BootstrapIPs, cfg.BootstrapMap))
		} else {
			resolvers = append(resolvers, NewStandardResolver(s, timeout))
		}
	}

	if len(resolvers) == 0 {
		return nil, fmt.Errorf("failed to initialize any upstream resolvers from config")
	}

	strategy := strings.ToLower(cfg.Strategy)
	if strategy == "" {
		strategy = "round_robin"
	}

	return &Forwarder{
		resolvers: resolvers,
		strategy:  strategy,
		timeout:   timeout,
		logger:    logger,
	}, nil
}

// Forward sends a DNS query to the upstream resolvers according to the configured strategy with failover.
func (f *Forwarder) Forward(ctx context.Context, req *dns.Msg) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	switch f.strategy {
	case "parallel":
		resp, err := f.forwardParallel(ctx, req)
		return resp, time.Since(start), err
	case "failover":
		resp, err := f.forwardFailover(ctx, req)
		return resp, time.Since(start), err
	case "round_robin":
		fallthrough
	default:
		resp, err := f.forwardRoundRobin(ctx, req)
		return resp, time.Since(start), err
	}
}

// forwardRoundRobin distributes queries across resolvers, falling back to others if the selected one fails.
func (f *Forwarder) forwardRoundRobin(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	n := len(f.resolvers)
	idx := int(atomic.AddUint64(&f.counter, 1) % uint64(n))

	var lastErr error
	for i := 0; i < n; i++ {
		target := f.resolvers[(idx+i)%n]
		qCtx, cancel := context.WithTimeout(ctx, f.timeout)
		resp, err := target.Exchange(qCtx, req)
		cancel()

		if err == nil && resp != nil {
			return resp, nil
		}

		lastErr = err
		f.logger.Debug("upstream query failed, attempting failover", "upstream", target.Address(), "error", err)
	}

	return nil, fmt.Errorf("all %d upstream servers failed (last error: %w)", n, lastErr)
}

// forwardFailover always prioritizes upstream servers in defined order.
func (f *Forwarder) forwardFailover(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, target := range f.resolvers {
		qCtx, cancel := context.WithTimeout(ctx, f.timeout)
		resp, err := target.Exchange(qCtx, req)
		cancel()

		if err == nil && resp != nil {
			return resp, nil
		}

		lastErr = err
		f.logger.Debug("upstream query failed, attempting next upstream", "upstream", target.Address(), "error", err)
	}

	return nil, fmt.Errorf("all upstream servers failed in failover mode (last error: %w)", lastErr)
}

// forwardParallel queries all upstreams concurrently; the first valid response wins.
func (f *Forwarder) forwardParallel(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	type result struct {
		resp *dns.Msg
		err  error
	}

	pCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan result, len(f.resolvers))

	for _, res := range f.resolvers {
		go func(r UpstreamResolver) {
			qCtx, qCancel := context.WithTimeout(pCtx, f.timeout)
			defer qCancel()

			// Clone request to avoid data races across goroutines
			clonedReq := req.Copy()
			resp, err := r.Exchange(qCtx, clonedReq)
			ch <- result{resp: resp, err: err}
		}(res)
	}

	var lastErr error
	for i := 0; i < len(f.resolvers); i++ {
		res := <-ch
		if res.err == nil && res.resp != nil {
			cancel() // cancel pending queries
			return res.resp, nil
		}
		lastErr = res.err
	}

	return nil, fmt.Errorf("all parallel upstreams failed (last error: %w)", lastErr)
}
