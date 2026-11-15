// Package api exposes the HTTP surface: JSON API, web UI and status endpoints.
package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/asoe/whois2api/internal/config"
	"github.com/asoe/whois2api/internal/lookup"
	"github.com/asoe/whois2api/internal/model"
	"github.com/asoe/whois2api/internal/version"
)

// batchConcurrency bounds how many domains one batch request resolves at once.
// Higher would just queue on the registry's own patience, and the engine
// already collapses duplicate keys.
const batchConcurrency = 8

// Server wires configuration, the lookup service and the HTTP handlers.
type Server struct {
	cfg     config.Config
	service *lookup.Service
	log     *slog.Logger
	limiter *limiter
	started time.Time
	// tokens is the lowered set of accepted API tokens.
	tokens map[string]struct{}
}

// NewServer builds the HTTP layer.
func NewServer(cfg config.Config, service *lookup.Service, log *slog.Logger) *Server {
	s := &Server{
		cfg:     cfg,
		service: service,
		log:     log,
		limiter: newLimiter(cfg.RateLimit, cfg.RateBurst),
		started: time.Now(),
		tokens:  make(map[string]struct{}, len(cfg.Tokens)),
	}
	for _, t := range cfg.Tokens {
		s.tokens[t] = struct{}{}
	}
	return s
}

// Handler returns the fully wrapped http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// JSON API.
	mux.HandleFunc("GET /api/v1/domain/{name}", s.handleDomain)
	mux.HandleFunc("GET /api/v1/whois/{name}", s.handleDomain) // alias
	mux.HandleFunc("POST /api/v1/batch", s.handleBatch)
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/tlds", s.handleTLDs)

	// Web UI and static assets.
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon-32.png", http.StatusMovedPermanently)
	})

	// Friendly errors for wrong methods on known paths.
	mux.HandleFunc("/api/v1/domain/{name}", methodNotAllowed(http.MethodGet))
	mux.HandleFunc("/api/v1/batch", methodNotAllowed(http.MethodPost))
	mux.HandleFunc("/api/v1/status", methodNotAllowed(http.MethodGet))

	return s.withRecovery(s.withRequestLog(s.withSecurityHeaders(mux)))
}

// methodNotAllowed answers a deterministic 405 instead of the default 404.
func methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		writeError(w, http.StatusMethodNotAllowed, CodeMethodNotAllowed,
			"Method "+r.Method+" is not allowed on this endpoint.",
			"Use "+allow+".")
	}
}

// withSecurityHeaders sets conservative headers. There is no third-party
// content, so the CSP can be strict.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

// withRecovery converts panics into 500s so one bad request cannot take the
// process down.
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic while handling request", "path", r.URL.Path, "panic", rec)
				writeError(w, http.StatusInternalServerError, CodeInternal,
					"The server hit an unexpected condition.",
					"Please report this with the request path.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withRequestLog logs one line per API request at debug level.
func (s *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			s.log.Debug("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"ms", time.Since(start).Milliseconds(),
			)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}

// authorize enforces the optional bearer token and the rate limit. It writes
// the failure response itself and reports whether the request may proceed.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	if !s.tokenOK(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="whois2api"`)
		writeError(w, http.StatusUnauthorized, CodeUnauthorized,
			"A valid API token is required.", "Send Authorization: Bearer <token>.")
		return false
	}
	ip := clientIP(r, s.trustedProxy)
	if allowed, wait := s.limiter.allow(ip, time.Now()); !allowed {
		seconds := int(wait.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", itoa(seconds))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited,
			"Rate limit exceeded.", "Retry in "+itoa(seconds)+"s, or raise W2A_RATE_LIMIT.")
		return false
	}
	return true
}

// tokenOK checks the bearer token when tokens are configured.
func (s *Server) tokenOK(r *http.Request) bool {
	if len(s.tokens) == 0 {
		return true // open mode
	}
	raw := r.Header.Get("Authorization")
	var presented string
	if len(raw) > 7 && strings.EqualFold(raw[:7], "bearer ") {
		presented = strings.TrimSpace(raw[7:])
	}
	if presented == "" {
		presented = r.URL.Query().Get("token")
	}
	if presented == "" {
		return false
	}
	// Constant-time comparison prevents token guessing via timing.
	for candidate := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(presented)) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) trustedProxy(ip net.IP) bool { return s.cfg.IsTrustedProxy(ip) }

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// handleDomain resolves one domain.
func (s *Server) handleDomain(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "Missing domain name.", "Use /api/v1/domain/example.com")
		return
	}

	var (
		result *lookup.ServiceResult
		err    error
	)
	if wantsFresh(r) {
		result, err = s.service.LookupFresh(r.Context(), name)
	} else {
		result, err = s.service.Lookup(r.Context(), name)
	}
	if err != nil {
		s.writeLookupError(w, err, "lookup failed", "domain", name)
		return
	}
	// The raw upstream payload is opt-in: it is useful when a verdict looks
	// surprising, and noise (plus bytes) the rest of the time.
	if result.Domain != nil {
		if wantsRaw(r) {
			if result.Domain.Raw == "" {
				// Cached entries deliberately store no payload. Say so, and
				// point at the flag that fixes it, instead of returning an
				// empty field the caller would read as "the registry said
				// nothing".
				if result.Meta.Cached {
					result.Meta.Warnings = append(result.Meta.Warnings, model.WarningCachedWithoutRaw)
				} else {
					result.Meta.Warnings = append(result.Meta.Warnings, model.WarningNoUpstreamPayload)
				}
			}
		} else {
			result.Domain.Raw = ""
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// wantsRaw reports whether the caller asked for the upstream payload.
func wantsRaw(r *http.Request) bool { return queryFlag(r, "raw") }

// wantsFresh reports whether the caller asked to bypass the cache. It exists
// for the one honest case where a cached answer is insufficient: fetching the
// raw payload of a name that is already cached.
func wantsFresh(r *http.Request) bool { return queryFlag(r, "fresh") }

func queryFlag(r *http.Request, key string) bool {
	switch strings.ToLower(r.URL.Query().Get(key)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// writeLookupError maps engine errors onto API responses.
func (s *Server) writeLookupError(w http.ResponseWriter, err error, logMsg string, args ...any) {
	switch {
	case errors.Is(err, lookup.ErrInvalidDomain):
		writeError(w, http.StatusBadRequest, CodeInvalidDomain,
			"That does not look like a valid domain name.",
			"Send a registrable name such as example.com; IDNs are accepted.")
	case errors.Is(err, lookup.ErrUnsupportedTLD):
		writeError(w, http.StatusNotFound, CodeUnsupportedTLD,
			"This top-level domain cannot be looked up automatically.",
			"Either it publishes no public WHOIS/RDAP service, or it is not a real TLD. "+
				"Run with W2A_REFRESH_TABLE=true to pick up newly delegated TLDs.")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, CodeUpstreamUnavailable,
			"The registries took too long to answer.", "Retry; results are cached once they succeed.")
	default:
		s.log.Error(logMsg, append(args, "error", err)...)
		status, code, msg, hint := asAPIError(err)
		writeError(w, status, code, msg, hint)
	}
}

// handleBatch resolves several domains in one request.
func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	var req struct {
		Domains []string `json:"domains"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest,
			"Request body must be JSON: {\"domains\": [\"example.com\"]}.", err.Error())
		return
	}
	if len(req.Domains) == 0 {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "No domains supplied.", `Send {"domains":["example.com"]}`)
		return
	}
	if len(req.Domains) > s.cfg.MaxBatch {
		writeError(w, http.StatusBadRequest, CodeTooManyItems,
			"Too many domains in one request.",
			"Send at most "+itoa(s.cfg.MaxBatch)+" per batch (see W2A_MAX_BATCH).")
		return
	}

	// Fan out: a batch of 20 uncached domains costs one registry round-trip,
	// not twenty. Results keep the caller's order.
	items := make([]model.BatchItem, len(req.Domains))
	var wg sync.WaitGroup
	sem := make(chan struct{}, batchConcurrency)
	for i, raw := range req.Domains {
		wg.Add(1)
		go func(i int, raw string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			item := model.BatchItem{Query: raw}
			res, err := s.service.Lookup(r.Context(), raw)
			if err != nil {
				item.Error = friendlyError(err)
			} else {
				// A batch has nowhere to ask for the payload and no per-item
				// flag to opt in: strip it. Left in, a five-domain cold batch
				// shipped ~11 KB of registry text nobody requested, while the
				// single-domain endpoint correctly sent none. Same answer,
				// different size, depending on which endpoint you called.
				if res.Domain != nil {
					res.Domain.Raw = ""
				}
				item.Domain = res.Domain
				item.Meta = res.Meta
			}
			items[i] = item
		}(i, raw)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, struct {
		Results []model.BatchItem `json:"results"`
		Count   int               `json:"count"`
	}{Results: items, Count: len(items)})
}

// friendlyError renders an error for a batch item without leaking internals.
func friendlyError(err error) string {
	switch {
	case errors.Is(err, lookup.ErrInvalidDomain):
		return "invalid domain name"
	case errors.Is(err, lookup.ErrUnsupportedTLD):
		return "unsupported top-level domain"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "registries did not answer in time"
	default:
		return "lookup failed"
	}
}

// handleStatus reports table coverage, cache counters and build info.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	tableStats, cacheStats := s.service.Stats()
	writeJSON(w, http.StatusOK, struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		Built     string `json:"built"`
		Go        string `json:"go"`
		UptimeSec int64  `json:"uptime_seconds"`
		TLD       any    `json:"tld_table"`
		Cache     any    `json:"cache"`
		RateLimit int    `json:"rate_limit_per_minute"`
		AuthMode  string `json:"auth_mode"`
	}{
		Version:   version.Version,
		Commit:    version.Commit,
		Built:     version.Date,
		Go:        goVersion(),
		UptimeSec: int64(time.Since(s.started).Seconds()),
		TLD:       tableStats,
		Cache:     cacheStats,
		RateLimit: s.cfg.RateLimit,
		AuthMode:  authMode(len(s.tokens) > 0),
	})
}

func authMode(enabled bool) string {
	if enabled {
		return "token"
	}
	return "open"
}

// handleHealth is a dependency-free liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleTLDs lists supported top-level domains.
func (s *Server) handleTLDs(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	table := s.service.Table()
	labels := table.Labels()
	writeJSON(w, http.StatusOK, struct {
		Count int      `json:"count"`
		TLDs  []string `json:"tlds"`
	}{Count: len(labels), TLDs: labels})
}
