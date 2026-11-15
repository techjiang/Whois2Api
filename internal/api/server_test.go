package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/asoe/whois2api/internal/cache"
	"github.com/asoe/whois2api/internal/config"
	"github.com/asoe/whois2api/internal/lookup"
	"github.com/asoe/whois2api/internal/model"
	"github.com/asoe/whois2api/internal/tld"
)

func newTestServer(t *testing.T, cfg config.Config) (*Server, *fakeUpstream) {
	t.Helper()
	if cfg.Listen == "" {
		cfg.Listen = ":0"
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Minute
	}
	if cfg.NegativeTTL == 0 {
		cfg.NegativeTTL = time.Minute
	}
	if cfg.MaxBatch == 0 {
		cfg.MaxBatch = 3
	}
	if cfg.TotalTimeout == 0 {
		cfg.TotalTimeout = time.Second
	}
	psl := tld.MustDefault()
	table, err := tld.EmbeddedTable()
	if err != nil {
		t.Fatal(err)
	}
	engine := lookup.New(psl, table, lookup.Options{
		RDAPTimeout: time.Second, WhoIsTimeout: time.Second, TotalTimeout: cfg.TotalTimeout,
	})
	store, err := cache.Open(cache.Options{Dir: t.TempDir(), TTL: time.Minute, NegativeTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	svc := lookup.NewService(engine, store)

	fake := &fakeUpstream{}
	lookup.SetTestHook(svc, fake.lookup)

	return NewServer(cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil))), fake
}

// fakeUpstream answers deterministically without touching the network.
type fakeUpstream struct{ calls int }

func (f *fakeUpstream) lookup(ctx context.Context, target *lookup.Target) (*model.Domain, []model.ChannelTiming, []string, error) {
	f.calls++
	status := model.VerdictRegistered
	if strings.HasPrefix(target.Query, "free-") {
		status = model.VerdictAvailable
	}
	return &model.Domain{
		Name: target.ASCII, TLD: target.TLD, Suffix: target.Suffix, Registrable: target.Registrable,
		Verdict: status, Confidence: model.ConfidenceStrong, Source: model.SourceRDAP,
		Registrar: "Test Registrar",
	}, nil, nil, nil
}

func doRequest(t *testing.T, s *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestDomainEndpointReturnsResult(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out lookup.ServiceResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if out.Domain == nil || out.Domain.Verdict != model.VerdictRegistered {
		t.Fatalf("unexpected payload: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content type = %q", ct)
	}
}

func TestInvalidDomainReturns400WithHint(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/not%20a%20domain", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	var e apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Error.Code != CodeInvalidDomain {
		t.Fatalf("code = %q", e.Error.Code)
	}
	if e.Error.Hint == "" {
		t.Fatal("errors should carry an actionable hint")
	}
}

func TestMethodNotAllowedIsDeterministic(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	rec := doRequest(t, s, http.MethodDelete, "/api/v1/domain/example.com", "", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow = %q", allow)
	}
}

func TestTokenAuthRequired(t *testing.T) {
	s, _ := newTestServer(t, config.Config{Tokens: []string{"secret-token"}})

	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	rec = doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", map[string]string{
		"Authorization": "Bearer wrong",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}
	rec = doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", map[string]string{
		"Authorization": "Bearer secret-token",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRateLimitReturns429WithRetryAfter(t *testing.T) {
	s, _ := newTestServer(t, config.Config{RateLimit: 2, RateBurst: 2})
	var last *httptest.ResponseRecorder
	for i := 0; i < 5; i++ {
		// Health is intentionally exempt from rate limiting so orchestrators
		// can always probe it; use a limited endpoint instead.
		last = doRequest(t, s, http.MethodGet, "/api/v1/tlds", "", nil)
		if last.Code == http.StatusTooManyRequests {
			break
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d after burst, want 429", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Fatal("429 must include Retry-After")
	}
	var e apiError
	if err := json.Unmarshal(last.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Error.Code != CodeRateLimited {
		t.Fatalf("code = %q", e.Error.Code)
	}
}

func TestBatchRespectsLimitAndShape(t *testing.T) {
	s, _ := newTestServer(t, config.Config{MaxBatch: 2})

	rec := doRequest(t, s, http.MethodPost, "/api/v1/batch",
		`{"domains":["a.com","b.com","c.com"]}`,
		map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-limit batch status = %d, want 400", rec.Code)
	}

	rec = doRequest(t, s, http.MethodPost, "/api/v1/batch",
		`{"domains":["ok.com","free-name.com"]}`,
		map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Results []model.BatchItem `json:"results"`
		Count   int               `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Count != 2 || len(out.Results) != 2 {
		t.Fatalf("count = %d, results = %d", out.Count, len(out.Results))
	}
	if out.Results[1].Domain == nil || out.Results[1].Domain.Verdict != model.VerdictAvailable {
		t.Fatalf("second result = %+v", out.Results[1])
	}
}

func TestBatchRejectsMalformedJSON(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	cases := []string{
		`{"domains": ["a.com"]} trailing`,
		`{"domains": "not-an-array"}`,
		`{"unknown_field": 1}`,
		`{`,
	}
	for _, body := range cases {
		rec := doRequest(t, s, http.MethodPost, "/api/v1/batch", body,
			map[string]string{"Content-Type": "application/json"})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestBatchEmptyListRejected(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	rec := doRequest(t, s, http.MethodPost, "/api/v1/batch", `{"domains":[]}`,
		map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	rec := doRequest(t, s, http.MethodGet, "/", "", nil)
	required := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, want := range required {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("missing Content-Security-Policy")
	}
}

func TestHealthAndStatus(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	rec := doRequest(t, s, http.MethodGet, "/api/v1/health", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}
	var health map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["status"] != "ok" {
		t.Fatalf("health = %v", health)
	}

	rec = doRequest(t, s, http.MethodGet, "/api/v1/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status endpoint = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tld_table") {
		t.Fatalf("status payload missing tld_table: %s", rec.Body.String())
	}
}

func TestIndexAndStaticAssets(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})

	rec := doRequest(t, s, http.MethodGet, "/", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Whois2Api") {
		t.Fatal("index page does not mention the product name")
	}

	for _, asset := range []string{"/static/app.css", "/static/app.js", "/static/logo.svg"} {
		rec := doRequest(t, s, http.MethodGet, asset, "", nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d", asset, rec.Code)
			continue
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s served an empty body", asset)
		}
	}
}

func TestStaticPathTraversalBlocked(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	for _, path := range []string{
		"/static/../index.html",
		"/static/..%2f..%2fetc/passwd",
		"/static/",
	} {
		rec := doRequest(t, s, http.MethodGet, path, "", nil)
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "root:") {
			t.Fatalf("%s leaked file content", path)
		}
	}
}

func TestPanicIsRecovered(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	lookup.SetTestHook(s.service, func(ctx context.Context, target *lookup.Target) (*model.Domain, []model.ChannelTiming, []string, error) {
		panic("boom")
	})
	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Fatal("panic detail leaked to the client")
	}
}
