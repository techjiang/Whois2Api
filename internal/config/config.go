// Package config loads runtime settings from environment variables with
// sensible, production-safe defaults and no required configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	// Listen is the TCP address the HTTP server binds to.
	Listen string
	// DataDir holds the embedded key/value cache and logs.
	DataDir string
	// Tokens are optional API tokens. When empty the API is open (fine for
	// private installs; the startup log says so explicitly).
	Tokens []string
	// RateLimit is the sustained per-client request budget per minute.
	// Zero disables rate limiting.
	RateLimit int
	// RateBurst is the bucket depth for bursts above RateLimit.
	RateBurst int
	// CacheTTL is how long a successful lookup stays fresh.
	CacheTTL time.Duration
	// NegativeTTL is how long an "available"/"not found" answer stays fresh.
	NegativeTTL time.Duration
	// StaleTTL is how long an expired entry may still be served while a
	// background refresh runs. Zero disables stale serving.
	StaleTTL time.Duration
	// RDAPTimeout bounds a single RDAP request.
	RDAPTimeout time.Duration
	// WhoIsTimeout bounds a single WHOIS socket exchange.
	WhoIsTimeout time.Duration
	// TotalTimeout bounds a whole lookup including fallbacks.
	TotalTimeout time.Duration
	// WhoIsFirst flips the default channel preference to WHOIS.
	WhoIsFirst bool
	// RDAPOnly disables the WHOIS fallback entirely.
	RDAPOnly bool
	// MaxBatch caps the number of domains accepted in one batch request.
	MaxBatch int
	// TrustedProxies enables X-Forwarded-For parsing for these CIDRs.
	TrustedProxies []*net.IPNet
	// RefreshTable fetches the IANA route table on boot.
	RefreshTable bool
	// LogLevel is "debug", "info", "warn" or "error".
	LogLevel string
}

// Default returns the configuration used when the environment is empty.
func Default() Config {
	return Config{
		Listen:       ":8080",
		DataDir:      "./data",
		RateLimit:    300,
		RateBurst:    60,
		CacheTTL:     30 * time.Minute,
		NegativeTTL:  5 * time.Minute,
		StaleTTL:     24 * time.Hour,
		RDAPTimeout:  6 * time.Second,
		WhoIsTimeout: 8 * time.Second,
		TotalTimeout: 12 * time.Second,
		MaxBatch:     20,
		LogLevel:     "info",
	}
}

// Load reads environment variables, validating each one.
func Load() (Config, error) {
	c := Default()
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	c.Listen = envString("W2A_LISTEN", c.Listen)
	c.DataDir = envString("W2A_DATA_DIR", c.DataDir)
	c.LogLevel = strings.ToLower(envString("W2A_LOG_LEVEL", c.LogLevel))

	if raw := strings.TrimSpace(os.Getenv("W2A_TOKENS")); raw != "" {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
			if part != "" {
				c.Tokens = append(c.Tokens, part)
			}
		}
	}

	c.RateLimit = envInt("W2A_RATE_LIMIT", c.RateLimit, fail)
	c.RateBurst = envInt("W2A_RATE_BURST", c.RateBurst, fail)
	c.MaxBatch = envInt("W2A_MAX_BATCH", c.MaxBatch, fail)
	c.CacheTTL = envDuration("W2A_CACHE_TTL", c.CacheTTL, fail)
	c.NegativeTTL = envDuration("W2A_NEGATIVE_TTL", c.NegativeTTL, fail)
	c.StaleTTL = envDuration("W2A_STALE_TTL", c.StaleTTL, fail)
	c.RDAPTimeout = envDuration("W2A_RDAP_TIMEOUT", c.RDAPTimeout, fail)
	c.WhoIsTimeout = envDuration("W2A_WHOIS_TIMEOUT", c.WhoIsTimeout, fail)
	c.TotalTimeout = envDuration("W2A_TOTAL_TIMEOUT", c.TotalTimeout, fail)
	c.WhoIsFirst = envBool("W2A_WHOIS_FIRST", c.WhoIsFirst, fail)
	c.RDAPOnly = envBool("W2A_RDAP_ONLY", c.RDAPOnly, fail)
	c.RefreshTable = envBool("W2A_REFRESH_TABLE", c.RefreshTable, fail)

	if raw := strings.TrimSpace(os.Getenv("W2A_TRUSTED_PROXIES")); raw != "" {
		nets, err := parseCIDRs(raw)
		if err != nil {
			fail("W2A_TRUSTED_PROXIES: %v", err)
		} else {
			c.TrustedProxies = nets
		}
	}

	if len(errs) > 0 {
		return c, errors.New("invalid configuration: " + strings.Join(errs, "; "))
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// Validate enforces cross-field invariants.
func (c Config) Validate() error {
	var errs []string
	if c.Listen == "" {
		errs = append(errs, "W2A_LISTEN must not be empty")
	}
	if c.DataDir == "" {
		errs = append(errs, "W2A_DATA_DIR must not be empty")
	}
	if c.RateLimit < 0 {
		errs = append(errs, "W2A_RATE_LIMIT must be >= 0")
	}
	if c.RateBurst < 0 {
		errs = append(errs, "W2A_RATE_BURST must be >= 0")
	}
	if c.RateLimit > 0 && c.RateBurst == 0 {
		errs = append(errs, "W2A_RATE_BURST must be > 0 when rate limiting is enabled")
	}
	if c.MaxBatch < 1 {
		errs = append(errs, "W2A_MAX_BATCH must be >= 1")
	}
	if c.CacheTTL <= 0 {
		errs = append(errs, "W2A_CACHE_TTL must be > 0")
	}
	if c.NegativeTTL <= 0 {
		errs = append(errs, "W2A_NEGATIVE_TTL must be > 0")
	}
	if c.StaleTTL < 0 {
		errs = append(errs, "W2A_STALE_TTL must be >= 0")
	}
	if c.RDAPTimeout <= 0 {
		errs = append(errs, "W2A_RDAP_TIMEOUT must be > 0")
	}
	if c.WhoIsTimeout <= 0 {
		errs = append(errs, "W2A_WHOIS_TIMEOUT must be > 0")
	}
	if c.TotalTimeout <= 0 {
		errs = append(errs, "W2A_TOTAL_TIMEOUT must be > 0")
	}
	if c.TotalTimeout < c.RDAPTimeout || c.TotalTimeout < c.WhoIsTimeout {
		errs = append(errs, "W2A_TOTAL_TIMEOUT must be >= the per-channel timeouts")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, `W2A_LOG_LEVEL must be one of "debug", "info", "warn", "error"`)
	}
	if len(errs) > 0 {
		return errors.New("invalid configuration: " + strings.Join(errs, "; "))
	}
	return nil
}

func envString(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int, fail func(string, ...any)) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		fail("%s must be an integer, got %q", key, raw)
		return def
	}
	return v
}

func envBool(key string, def bool, fail func(string, ...any)) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		fail("%s must be a boolean (true/false/1/0), got %q", key, raw)
		return def
	}
	return v
}

func envDuration(key string, def time.Duration, fail func(string, ...any)) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		fail("%s must be a duration such as 30s or 10m, got %q", key, raw)
		return def
	}
	return v
}

func parseCIDRs(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR", item)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			item = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid CIDR: %w", item, err)
		}
		out = append(out, network)
	}
	return out, nil
}

// IsTrustedProxy reports whether ip belongs to a configured trusted proxy range.
func (c Config) IsTrustedProxy(ip net.IP) bool {
	for _, n := range c.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
