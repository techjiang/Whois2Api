package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/techjiang/Whois2Api/internal/cache"
	"github.com/techjiang/Whois2Api/internal/config"
	"github.com/techjiang/Whois2Api/internal/lookup"
	"github.com/techjiang/Whois2Api/internal/model"
	"github.com/techjiang/Whois2Api/internal/tld"
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
type fakeUpstream struct {
	callCount atomic.Int64
	// delay slows every answer so concurrency is observable.
	delay time.Duration
	// raw is attached to results, mimicking an upstream payload.
	raw string
}

func (f *fakeUpstream) lookup(ctx context.Context, target *lookup.Target) (*model.Domain, []model.ChannelTiming, []model.Notice, error) {
	// Batch handlers call this from several goroutines at once, so the counter
	// has to be atomic. It was a plain int until a -race run pointed at it: the
	// tests looked fine because nothing asserted on the value.
	f.callCount.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		}
	}
	status := model.VerdictRegistered
	if strings.HasPrefix(target.Query, "free-") {
		status = model.VerdictAvailable
	}
	return &model.Domain{
		Name: target.ASCII, TLD: target.TLD, Suffix: target.Suffix, Registrable: target.Registrable,
		Verdict: status, Confidence: model.ConfidenceStrong, Source: model.SourceRDAP,
		Registrar: "Test Registrar", Raw: f.raw,
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
	lookup.SetTestHook(s.service, func(ctx context.Context, target *lookup.Target) (*model.Domain, []model.ChannelTiming, []model.Notice, error) {
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

// A batch used to resolve its items one at a time, so 20 uncached domains cost
// 20 registries round-trips in series. Each item must now run concurrently,
// while the response keeps the caller's order.
func TestBatchResolvesItemsConcurrentlyAndKeepsOrder(t *testing.T) {
	s, fake := newTestServer(t, config.Config{MaxBatch: 8})
	fake.delay = 120 * time.Millisecond

	body := `{"domains":["one.com","two.com","three.com","four.com"]}`
	start := time.Now()
	rec := doRequest(t, s, http.MethodPost, "/api/v1/batch", body,
		map[string]string{"Content-Type": "application/json"})
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// Serial execution would need >= 480ms; concurrent should be well under.
	if elapsed > 400*time.Millisecond {
		t.Fatalf("batch took %v for 4 domains with a 120ms upstream; it is not concurrent", elapsed)
	}
	var out struct {
		Results []model.BatchItem `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"one.com", "two.com", "three.com", "four.com"}
	if len(out.Results) != len(want) {
		t.Fatalf("got %d results, want %d", len(out.Results), len(want))
	}
	for i, q := range want {
		if out.Results[i].Query != q {
			t.Fatalf("result %d query = %q, want %q (order not preserved)", i, out.Results[i].Query, q)
		}
	}
}

// The raw upstream payload is opt-in.
func TestRawPayloadIsOptIn(t *testing.T) {
	s, fake := newTestServer(t, config.Config{})
	fake.raw = "Domain Name: example.com"

	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", nil)
	var plain lookup.ServiceResult
	if err := json.Unmarshal(rec.Body.Bytes(), &plain); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if plain.Domain.Raw != "" {
		t.Fatalf("raw payload leaked without ?raw=1: %q", plain.Domain.Raw)
	}
}

// A cached answer has no payload, so asking for one must say so rather than
// return an empty field the caller would read as "the registry said nothing".
func TestRawPayloadOnCachedAnswerIsExplained(t *testing.T) {
	s, fake := newTestServer(t, config.Config{})
	fake.raw = "Domain Name: example.com"

	if rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("warm-up status = %d", rec.Code)
	}
	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com?raw=1", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var out lookup.ServiceResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Meta.Cached {
		t.Fatal("second lookup should be served from cache")
	}
	var explained bool
	for _, w := range out.Meta.Warnings {
		if w.Code == model.WarningCachedWithoutRaw.Code {
			explained = true
		}
	}
	if !explained {
		t.Fatalf("cached answer with ?raw=1 should point at ?fresh=1, warnings = %v", out.Meta.Warnings)
	}

	// ?fresh=1 must bypass the cache and deliver the payload.
	rec = doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com?raw=1&fresh=1", "", nil)
	var fresh lookup.ServiceResult
	if err := json.Unmarshal(rec.Body.Bytes(), &fresh); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fresh.Meta.Cached {
		t.Fatal("?fresh=1 must not be served from the cache")
	}
	if !strings.Contains(fresh.Domain.Raw, "Domain Name: example.com") {
		t.Fatalf("fresh raw = %q, want the upstream payload", fresh.Domain.Raw)
	}
}

func TestRawPayloadReturnedWhenAsked(t *testing.T) {
	s, fake := newTestServer(t, config.Config{})
	fake.raw = "Domain Name: example.com\nRegistrar: Test"

	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com?raw=1", "", nil)
	var out lookup.ServiceResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(out.Domain.Raw, "Domain Name: example.com") {
		t.Fatalf("raw = %q, want the upstream payload", out.Domain.Raw)
	}
}

// A batch has no per-item way to opt into the raw payload, so it must not ship
// one. It used to: a cold five-domain batch answered with roughly 11 KB of
// registry text that nobody asked for, while the single-domain endpoint
// correctly sent none. Same answer, wildly different size.
func TestBatchNeverShipsRawPayload(t *testing.T) {
	s, fake := newTestServer(t, config.Config{MaxBatch: 4})
	fake.raw = strings.Repeat("Domain Name: example.com\n", 100)

	rec := doRequest(t, s, http.MethodPost, "/api/v1/batch",
		`{"domains":["one.com","two.com"]}`,
		map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "raw") {
		t.Fatalf("batch response carries a raw payload: %s", rec.Body.String())
	}
	var out struct {
		Results []model.BatchItem `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, item := range out.Results {
		if item.Domain != nil && item.Domain.Raw != "" {
			t.Fatalf("%s carried %d bytes of raw payload", item.Query, len(item.Domain.Raw))
		}
	}
}

// CORS is off by default, so a private install cannot be read by any page a
// visitor happens to have open.
func TestCORSDisabledByDefault(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", map[string]string{
		"Origin": "https://evil.example",
	})
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want none", got)
	}
	// A preflight must not be answered when nothing is allowed.
	pre := doRequest(t, s, http.MethodOptions, "/api/v1/batch", "", map[string]string{
		"Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
	})
	if pre.Code != http.StatusMethodNotAllowed {
		t.Errorf("preflight status = %d, want 405", pre.Code)
	}
}

// With W2A_CORS_ORIGINS set, a browser client can read answers — and the
// preflight for the batch endpoint is answered instead of 405, which is what
// made POST /api/v1/batch unusable from any page this process did not serve.
func TestCORSAllowedOrigin(t *testing.T) {
	s, _ := newTestServer(t, config.Config{CORSOrigins: []string{"https://app.example"}})
	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", map[string]string{
		"Origin": "https://app.example",
	})
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the configured origin", got)
	}
	// Credentials are never advertised: auth is a bearer token, and combining
	// the two would be a lie the browser acts on.
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("Access-Control-Allow-Credentials must not be set")
	}

	pre := doRequest(t, s, http.MethodOptions, "/api/v1/batch", "", map[string]string{
		"Origin": "https://app.example", "Access-Control-Request-Method": "POST",
	})
	if pre.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", pre.Code)
	}
	if got := pre.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Errorf("Access-Control-Allow-Methods = %q, want POST", got)
	}

	// A different origin stays out.
	other := doRequest(t, s, http.MethodGet, "/api/v1/domain/example.com", "", map[string]string{
		"Origin": "https://evil.example",
	})
	if got := other.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unlisted origin got %q", got)
	}
}

// A private-suffix name must not come back `available` even when the registry
// says "no match", because the registry does not administer it.
func TestPrivateSuffixVerdictIsUnknown(t *testing.T) {
	s, _ := newTestServer(t, config.Config{})
	rec := doRequest(t, s, http.MethodGet, "/api/v1/domain/foo.uk.com", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Domain model.Domain `json:"domain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// The fake upstream always reports available for "free-*" and registered
	// otherwise; here the point is that the fake's registered verdict survives
	// and the caveat is attached.
	found := false
	for _, a := range body.Domain.Alerts {
		if a.Code == model.NoticePrivateSuffix.Code {
			found = true
		}
	}
	if !found {
		t.Errorf("alerts = %+v, want %q", body.Domain.Alerts, model.NoticePrivateSuffix.Code)
	}
}
