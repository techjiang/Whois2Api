// Command whois2api serves a self-hosted domain WHOIS/RDAP lookup API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/asoe/whois2api/internal/api"
	"github.com/asoe/whois2api/internal/cache"
	"github.com/asoe/whois2api/internal/config"
	"github.com/asoe/whois2api/internal/lookup"
	"github.com/asoe/whois2api/internal/tld"
	"github.com/asoe/whois2api/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Subcommands keep the binary usable as a single self-contained tool.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println(version.String())
			return nil
		case "healthcheck":
			return healthcheck()
		case "help", "-h", "--help":
			usage()
			return nil
		}
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)
	logger.Info("starting", "version", version.Version, "commit", version.Commit)

	psl, err := tld.Default()
	if err != nil {
		return fmt.Errorf("load public suffix list: %w", err)
	}
	table, err := loadRouteTable(cfg, logger)
	if err != nil {
		return err
	}
	logger.Info("route table ready", "source", table.Source(), "tlds", table.Len(), "public_suffix_rules", psl.RuleCount())

	store, err := cache.Open(cache.Options{
		Dir:         cfg.DataDir,
		TTL:         cfg.CacheTTL,
		NegativeTTL: cfg.NegativeTTL,
		StaleWindow: cfg.StaleTTL,
	})
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			logger.Error("closing cache", "error", closeErr)
		}
	}()
	logger.Info("cache ready", "path", store.Path(), "entries", store.Count())

	engine := lookup.New(psl, table, lookup.Options{
		RDAPTimeout:  cfg.RDAPTimeout,
		WhoIsTimeout: cfg.WhoIsTimeout,
		TotalTimeout: cfg.TotalTimeout,
		PreferWhoIs:  cfg.WhoIsFirst,
		RDAPOnly:     cfg.RDAPOnly,
		ResolveDNS:   true,
	})
	service := lookup.NewService(engine, store)

	srv := api.NewServer(cfg, service, logger)
	httpServer := &http.Server{
		Addr:    cfg.Listen,
		Handler: srv.Handler(),
		// ReadHeaderTimeout defends against slowloris; the rest bound misuse.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		BaseContext:       func(net.Listener) context.Context { return context.Background() },
	}

	// Bind first so a port conflict fails fast and clearly.
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	if len(cfg.Tokens) == 0 {
		logger.Warn("running without API tokens: anyone who can reach this port can query it",
			"hint", "set W2A_TOKENS to require Authorization: Bearer <token>")
	}
	logger.Info("listening", "addr", listener.Addr().String(),
		"rate_limit_per_min", cfg.RateLimit, "auth", authMode(len(cfg.Tokens) > 0))

	serveErr := make(chan error, 1)
	go func() {
		if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case sig := <-stop:
		logger.Info("shutting down", "signal", sig.String())
	}

	// Give in-flight requests room to finish; the cache is flushed by Close.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		_ = httpServer.Close()
	}
	<-serveErr
	logger.Info("stopped")
	return nil
}

func authMode(enabled bool) string {
	if enabled {
		return "token"
	}
	return "open"
}

// loadRouteTable prefers the embedded table (works fully offline) and only
// reaches the network when explicitly asked to refresh.
func loadRouteTable(cfg config.Config, logger *slog.Logger) (*tld.Table, error) {
	embedded, err := tld.EmbeddedTable()
	if err != nil {
		return nil, err
	}
	if !cfg.RefreshTable {
		return embedded, nil
	}
	// A failed refresh must not stop the service: the embedded table is a
	// complete, valid fallback.
	table, refreshErr := tld.FetchIANA(context.Background())
	if refreshErr != nil {
		logger.Warn("IANA table refresh failed, using embedded table", "error", refreshErr)
		return embedded, nil
	}
	if err := tld.SaveTable(cfg.DataDir, table); err != nil {
		logger.Warn("could not persist refreshed table", "error", err)
	}
	return table, nil
}

// healthcheck lets container orchestrators probe a running instance without
// requiring curl inside the image.
func healthcheck() error {
	port := os.Getenv("W2A_LISTEN")
	if port == "" {
		port = ":8080"
	}
	_, p, err := net.SplitHostPort(port)
	if err != nil {
		p = "8080"
	}
	url := "http://127.0.0.1:" + p + "/api/v1/health"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: status %d", resp.StatusCode)
	}
	return nil
}

func usage() {
	out := os.Stdout
	fmt.Fprintf(out, `whois2api %s

Usage:
  whois2api            start the HTTP server
  whois2api version    print build information
  whois2api healthcheck probe a local instance

Environment:
  W2A_LISTEN         bind address (default :8080)
  W2A_DATA_DIR       cache directory (default ./data)
  W2A_TOKENS         comma-separated API tokens; empty disables auth
  W2A_RATE_LIMIT     requests per minute per client (default 300, 0 disables)
  W2A_RATE_BURST     burst allowance (default 60)
  W2A_CACHE_TTL      registered-answer cache lifetime (default 30m)
  W2A_NEGATIVE_TTL   available-answer cache lifetime (default 5m)
  W2A_STALE_TTL      stale-while-revalidate window (default 24h)
  W2A_RDAP_TIMEOUT   per-RDAP timeout (default 6s)
  W2A_WHOIS_TIMEOUT  per-WHOIS timeout (default 8s)
  W2A_TOTAL_TIMEOUT  whole-lookup timeout (default 12s)
  W2A_MAX_BATCH      batch size cap (default 20)
  W2A_TRUSTED_PROXIES comma-separated CIDRs allowed to set X-Forwarded-For
  W2A_REFRESH_TABLE  fetch the IANA TLD table on boot (default false)
  W2A_RDAP_ONLY      skip WHOIS entirely (default false)
  W2A_LOG_LEVEL      debug|info|warn|error (default info)

Docs: https://github.com/asoe/whois2api
`, version.Version)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler)
}
