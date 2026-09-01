package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tuxdnshole/internal/config"
	"tuxdnshole/internal/dns"
	"tuxdnshole/internal/filter"
	"tuxdnshole/internal/upstream"
)

const (
	Version   = "1.0.0"
	BannerStr = `
  _____            ____  _   _ ____       _   _       _      
 |_   _|   ___  __|  _ \| \ | / ___|     | | | | ___ | | ___ 
   | || | | \ \/ /| | | |  \| \___ \ ____| |_| |/ _ \| |/ _ \
   | || |_| |>  < | |_| | |\  |___) |____|  _  | (_) | |  __/
   |_| \__,_/_/\_\|____/|_| \_|____/     |_| |_|\___/|_|\___|
  Local High-Performance DNS Sinkhole Daemon (OpSec / Zero-Log)
`
)

func main() {
	configPath := flag.String("config", "", "Path to YAML configuration file (default: configs/config.yaml or /etc/tuxdnshole/config.yaml)")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	shortVersion := flag.Bool("v", false, "Print version information and exit (short)")
	debugFlag := flag.Bool("debug", false, "Force debug log level")
	testConfig := flag.Bool("test-config", false, "Validate configuration file syntax and exit")
	flag.Parse()

	if *showVersion || *shortVersion {
		fmt.Printf("TuxDNS-Hole v%s (Linux amd64/arm64)\n", Version)
		os.Exit(0)
	}

	fmt.Print(BannerStr)

	// Resolve config path fallback
	resolvedPath := *configPath
	if resolvedPath == "" {
		candidates := []string{
			"configs/config.yaml",
			"configs/config.example.yaml",
			"/etc/tuxdnshole/config.yaml",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				resolvedPath = c
				break
			}
		}
	}

	// 1. Load Configuration
	cfg, err := config.Load(resolvedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	if *testConfig {
		fmt.Println("Configuration is valid.")
		os.Exit(0)
	}

	// 2. Pre-flight Port Conflict Check
	listenAddrs := cfg.Server.GetListenAddrs()
	if err := checkPortAvailability(listenAddrs); err != nil {
		fmt.Fprintf(os.Stderr, "\n[FATAL PORT CONFLICT]\n%s\n", err.Error())
		os.Exit(1)
	}

	// 3. Setup Structured Logger (slog)
	logLevel := slog.LevelInfo
	if *debugFlag || strings.ToLower(cfg.OpSec.LogLevel) == "debug" {
		logLevel = slog.LevelDebug
	} else if strings.ToLower(cfg.OpSec.LogLevel) == "warn" {
		logLevel = slog.LevelWarn
	} else if strings.ToLower(cfg.OpSec.LogLevel) == "error" {
		logLevel = slog.LevelError
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	logger.Info("starting TuxDNS-Hole daemon",
		"version", Version,
		"config_file", resolvedPath,
		"listen_addrs", listenAddrs,
		"zero_log", cfg.OpSec.ZeroLog,
		"block_mode", cfg.Blocking.BlockMode,
	)

	// 4. Initialize Root Context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 5. Initialize Filter Engine
	filterEngine := filter.NewEngine(&cfg.Blocking, logger)
	if cfg.Blocking.Enabled {
		logger.Info("loading blocklists and whitelist...")
		if err := filterEngine.LoadRules(ctx); err != nil {
			logger.Error("failed to load initial filter rules", "error", err)
		}
		filterEngine.StartAutoUpdate(ctx)
	}

	// 6. Initialize Upstream Forwarder with Bootstrap Resolvers
	forwarder, err := upstream.NewForwarder(&cfg.Upstream, logger)
	if err != nil {
		logger.Error("failed to initialize upstream forwarder", "error", err)
		os.Exit(1)
	}

	// 7. Initialize LRU Cache
	cache := dns.NewCache(&cfg.Cache)
	if cfg.Cache.Enabled {
		logger.Info("DNS LRU cache initialized", "max_size", cfg.Cache.Size, "min_ttl", cfg.Cache.MinTTL.String())
	}

	// 8. Initialize DNS Handler & Multi-address Server
	dnsHandler := dns.NewHandler(cfg, filterEngine, forwarder, cache, logger)
	server := dns.NewServer(&cfg.Server, dnsHandler, logger)

	// 9. Setup Signal Handling (Graceful Shutdown & SIGHUP live reload)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("received SIGHUP, triggering live reload of blocklists...")
				reloadCtx, reloadCancel := context.WithTimeout(context.Background(), 60*time.Second)
				if err := filterEngine.LoadRules(reloadCtx); err != nil {
					logger.Error("failed to reload filter rules on SIGHUP", "error", err)
				}
				reloadCancel()
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("received termination signal, initiating graceful shutdown...", "signal", sig.String())
				cancel()

				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := server.Shutdown(shutdownCtx); err != nil {
					logger.Error("error during server shutdown", "error", err)
				}
				shutdownCancel()
				os.Exit(0)
			}
		}
	}()

	// 10. Run Server
	logger.Info("TuxDNS-Hole is ready to serve requests", "listeners", listenAddrs)
	if err := server.Start(); err != nil {
		logger.Error("fatal DNS server error", "error", err)
		os.Exit(1)
	}
}

// checkPortAvailability performs pre-flight test bindings to detect conflicts like systemd-resolved.
func checkPortAvailability(addrs []string) error {
	for _, addr := range addrs {
		// Test UDP binding
		uConn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return formatPortConflictError("UDP", addr, err)
		}
		_ = uConn.Close()

		// Test TCP binding
		tConn, err := net.Listen("tcp", addr)
		if err != nil {
			return formatPortConflictError("TCP", addr, err)
		}
		_ = tConn.Close()
	}
	return nil
}

// formatPortConflictError formats a user-friendly error with guidance for systemd-resolved.
func formatPortConflictError(proto, addr string, err error) error {
	var opErr *net.OpError
	isAddrInUse := false
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EADDRINUSE) || strings.Contains(opErr.Err.Error(), "address already in use") {
			isAddrInUse = true
		}
	} else if strings.Contains(err.Error(), "address already in use") {
		isAddrInUse = true
	}

	if isAddrInUse {
		return fmt.Errorf(`Failed to bind %s listener to %s: Address already in use.

Port 53 is already occupied by another service (typically systemd-resolved or dnsmasq).

To free port 53 in systemd-resolved:
  1. Edit /etc/systemd/resolved.conf:
       [Resolve]
       DNSStubListener=no
  2. Restart systemd-resolved:
       sudo systemctl restart systemd-resolved
  3. Symlink /etc/resolv.conf:
       sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

Or test on a custom non-root port in config:
  server:
    listen_addrs:
      - "127.0.0.1:1053"
      - "[::1]:1053"`, proto, addr)
	}

	return fmt.Errorf("failed to bind %s listener to %s: %w", proto, addr, err)
}
