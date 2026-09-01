package dns

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/miekg/dns"
	"tuxdnshole/internal/config"
)

// Server coordinates UDP and TCP DNS listeners across multiple IPv4/IPv6 addresses (dual-stack).
type Server struct {
	cfg        *config.ServerConfig
	handler    *Handler
	logger     *slog.Logger
	udpServers []*dns.Server
	tcpServers []*dns.Server
	addrs      []string
}

// NewServer creates a new DNS Server instance supporting dual-stack IPv4/IPv6 binding.
func NewServer(cfg *config.ServerConfig, handler *Handler, logger *slog.Logger) *Server {
	addrs := cfg.GetListenAddrs()
	s := &Server{
		cfg:     cfg,
		handler: handler,
		logger:  logger,
		addrs:   addrs,
	}

	for _, addr := range addrs {
		udp := &dns.Server{
			Addr:         addr,
			Net:          "udp",
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
		}
		tcp := &dns.Server{
			Addr:         addr,
			Net:          "tcp",
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
		}
		s.udpServers = append(s.udpServers, udp)
		s.tcpServers = append(s.tcpServers, tcp)
	}

	return s
}

// Start launches all UDP and TCP DNS servers concurrently and returns if any listener fails.
func (s *Server) Start() error {
	totalListeners := len(s.udpServers) + len(s.tcpServers)
	errCh := make(chan error, totalListeners)

	for i, addr := range s.addrs {
		udpServer := s.udpServers[i]
		tcpServer := s.tcpServers[i]

		// Start UDP Listener
		go func(a string, srv *dns.Server) {
			s.logger.Info("starting DNS UDP listener", "addr", a)
			if err := srv.ListenAndServe(); err != nil {
				errCh <- fmt.Errorf("udp listener error (%s): %w", a, err)
			}
		}(addr, udpServer)

		// Start TCP Listener
		go func(a string, srv *dns.Server) {
			s.logger.Info("starting DNS TCP listener", "addr", a)
			if err := srv.ListenAndServe(); err != nil {
				errCh <- fmt.Errorf("tcp listener error (%s): %w", a, err)
			}
		}(addr, tcpServer)
	}

	return <-errCh
}

// Shutdown gracefully stops all UDP and TCP DNS listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down all DNS listeners...")

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	for _, srv := range s.udpServers {
		wg.Add(1)
		go func(s *dns.Server) {
			defer wg.Done()
			if err := s.ShutdownContext(ctx); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("udp shutdown error (%s): %w", s.Addr, err))
				mu.Unlock()
			}
		}(srv)
	}

	for _, srv := range s.tcpServers {
		wg.Add(1)
		go func(s *dns.Server) {
			defer wg.Done()
			if err := s.ShutdownContext(ctx); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("tcp shutdown error (%s): %w", s.Addr, err))
				mu.Unlock()
			}
		}(srv)
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("errors during DNS shutdown: %v", errs)
	}

	s.logger.Info("all DNS listeners successfully stopped")
	return nil
}
