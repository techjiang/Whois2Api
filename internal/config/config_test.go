package config

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.DataDir != "./data" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.RateLimit <= 0 || cfg.CacheTTL <= 0 {
		t.Fatalf("defaults should enable caching and rate limiting: %+v", cfg)
	}
	if len(cfg.Tokens) != 0 {
		t.Fatal("no tokens by default")
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"W2A_RATE_LIMIT":   "not-a-number",
		"W2A_CACHE_TTL":    "soon",
		"W2A_MAX_BATCH":    "0",
		"W2A_LOG_LEVEL":    "verbose",
		"W2A_RDAP_TIMEOUT": "-3s",
	}
	for key, value := range cases {
		t.Run(key, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(key, value)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%q should be rejected", key, value)
			} else if !strings.Contains(err.Error(), key) {
				t.Fatalf("error should name the variable: %v", err)
			}
		})
	}
}

func TestLoadParsesValues(t *testing.T) {
	clearEnv(t)
	t.Setenv("W2A_LISTEN", "127.0.0.1:9000")
	t.Setenv("W2A_TOKENS", "a, b ,c")
	t.Setenv("W2A_CACHE_TTL", "45m")
	t.Setenv("W2A_MAX_BATCH", "7")
	t.Setenv("W2A_RDAP_ONLY", "true")
	t.Setenv("W2A_TRUSTED_PROXIES", "10.0.0.0/8,192.168.1.5")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if len(cfg.Tokens) != 3 || cfg.Tokens[0] != "a" || cfg.Tokens[2] != "c" {
		t.Fatalf("tokens = %v", cfg.Tokens)
	}
	if cfg.CacheTTL != 45*time.Minute {
		t.Fatalf("cache ttl = %v", cfg.CacheTTL)
	}
	if cfg.MaxBatch != 7 || !cfg.RDAPOnly {
		t.Fatalf("batch/rdap = %d/%v", cfg.MaxBatch, cfg.RDAPOnly)
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies = %d", len(cfg.TrustedProxies))
	}
}

func TestTrustedProxyMatching(t *testing.T) {
	clearEnv(t)
	t.Setenv("W2A_TRUSTED_PROXIES", "10.0.0.0/8")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsTrustedProxy(mustIP(t, "10.1.2.3")) {
		t.Fatal("10.1.2.3 should be trusted")
	}
	if cfg.IsTrustedProxy(mustIP(t, "8.8.8.8")) {
		t.Fatal("8.8.8.8 should not be trusted")
	}
}

func TestTotalTimeoutMustCoverChannelTimeouts(t *testing.T) {
	clearEnv(t)
	t.Setenv("W2A_TOTAL_TIMEOUT", "1s")
	t.Setenv("W2A_RDAP_TIMEOUT", "10s")
	if _, err := Load(); err == nil {
		t.Fatal("total timeout shorter than a channel timeout must be rejected")
	}
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"W2A_LISTEN", "W2A_DATA_DIR", "W2A_TOKENS", "W2A_RATE_LIMIT", "W2A_RATE_BURST",
		"W2A_MAX_BATCH", "W2A_CACHE_TTL", "W2A_NEGATIVE_TTL", "W2A_STALE_TTL",
		"W2A_RDAP_TIMEOUT", "W2A_WHOIS_TIMEOUT", "W2A_TOTAL_TIMEOUT", "W2A_WHOIS_FIRST",
		"W2A_RDAP_ONLY", "W2A_REFRESH_TABLE", "W2A_TRUSTED_PROXIES", "W2A_LOG_LEVEL",
	} {
		t.Setenv(key, "")
	}
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	parsed := net.ParseIP(s)
	if parsed == nil {
		t.Fatalf("bad ip %q", s)
	}
	return parsed
}
