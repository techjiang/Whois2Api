package lookup

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asoe/whois2api/internal/cache"
	"github.com/asoe/whois2api/internal/model"
	"github.com/asoe/whois2api/internal/tld"
)

// fakeResolver lets tests drive the engine deterministically without network.
type fakeResolver struct {
	mu    sync.Mutex
	calls []string
	reply func(name string) (*model.Domain, []model.ChannelTiming, []model.Notice)
	delay time.Duration
	count atomic.Int64
}

func newTestService(t *testing.T, fake *fakeResolver, ttl, negTTL, stale time.Duration) *Service {
	t.Helper()
	psl := tld.MustDefault()
	table, err := tld.EmbeddedTable()
	if err != nil {
		t.Fatal(err)
	}
	engine := New(psl, table, Options{RDAPTimeout: time.Second, WhoIsTimeout: time.Second, TotalTimeout: 2 * time.Second})
	// Swap the network clients for the fake via a test hook.
	store, err := cache.Open(cache.Options{Dir: t.TempDir(), TTL: ttl, NegativeTTL: negTTL, StaleWindow: stale})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	svc := NewService(engine, store)
	svc.lookupHook = fake.lookup
	return svc
}

func (f *fakeResolver) lookup(ctx context.Context, t *Target) (*model.Domain, []model.ChannelTiming, []model.Notice, error) {
	f.mu.Lock()
	f.calls = append(f.calls, t.Query)
	f.mu.Unlock()
	f.count.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		}
	}
	dom, timings, warns := f.reply(t.Query)
	dom.Name = t.ASCII
	dom.TLD = t.TLD
	dom.Suffix = t.Suffix
	dom.Registrable = t.Registrable
	return dom, timings, warns, nil
}

func TestLookupCachesResult(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		return &model.Domain{Verdict: model.VerdictRegistered, Source: model.SourceRDAP, Registrar: "R"}, nil, nil
	}}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)

	first, err := svc.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if first.Meta.Cached {
		t.Fatal("first lookup should not be cached")
	}
	second, err := svc.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if !second.Meta.Cached {
		t.Fatal("second lookup should hit the cache")
	}
	if got := fake.count.Load(); got != 1 {
		t.Fatalf("upstream called %d times, want 1", got)
	}
}

func TestLookupSharesCacheAcrossSubdomains(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		return &model.Domain{Verdict: model.VerdictRegistered, Registrar: "R"}, nil, nil
	}}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)

	if _, err := svc.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	// A subdomain must reuse the parent's cached record instead of a new query.
	res, err := svc.Lookup(context.Background(), "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := fake.count.Load(); got != 1 {
		t.Fatalf("upstream called %d times, want 1 (should reuse parent)", got)
	}
	if res.Domain.Input != "www.example.com" {
		t.Fatalf("Input = %q, want the caller's name", res.Domain.Input)
	}
	if res.Domain.SubdomainOf != "example.com" {
		t.Fatalf("SubdomainOf = %q", res.Domain.SubdomainOf)
	}
}

func TestAvailableParentNeverMarksSubdomainAvailable(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		// The registrable domain is free...
		return &model.Domain{Verdict: model.VerdictAvailable, Source: model.SourceRDAP}, nil, nil
	}}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)

	// ...but asking about a subdomain must not claim the *subdomain* is free.
	res, err := svc.Lookup(context.Background(), "www.free-example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Domain.Verdict == model.VerdictAvailable {
		var flagged bool
		for _, a := range res.Domain.Alerts {
			if a.Code != "" {
				flagged = true
			}
		}
		if !flagged {
			t.Fatal("subdomain of an available domain must be explained, not silently reported available")
		}
	}
}

func TestConcurrentLookupsCollapseToOneUpstreamCall(t *testing.T) {
	fake := &fakeResolver{
		delay: 150 * time.Millisecond,
		reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
			return &model.Domain{Verdict: model.VerdictRegistered, Registrar: "R"}, nil, nil
		},
	}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)

	const callers = 25
	var wg sync.WaitGroup
	wg.Add(callers)
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		go func(n int) {
			defer wg.Done()
			_, err := svc.Lookup(context.Background(), "example.com")
			errs[n] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d failed: %v", i, err)
		}
	}
	if got := fake.count.Load(); got != 1 {
		t.Fatalf("upstream called %d times for %d concurrent callers, want 1", got, callers)
	}
}

func TestStaleEntryServedWhileRefreshing(t *testing.T) {
	var mode atomic.Value
	mode.Store("first")
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		return &model.Domain{Verdict: model.VerdictRegistered, Registrar: mode.Load().(string)}, nil, nil
	}}
	// Positive TTL is tiny so the entry goes stale immediately.
	svc := newTestService(t, fake, 40*time.Millisecond, 40*time.Millisecond, time.Hour)

	if _, err := svc.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	mode.Store("refreshed")

	start := time.Now()
	res, err := svc.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("stale hit took %v; it should return immediately", elapsed)
	}
	if !res.Meta.Stale {
		t.Fatal("expected a stale-while-revalidate response")
	}
	if res.Domain.Registrar != "first" {
		t.Fatalf("stale response should carry the old value, got %q", res.Domain.Registrar)
	}

	// The background refresh must eventually replace the entry.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
		again, err := svc.Lookup(context.Background(), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		if again.Domain.Registrar == "refreshed" {
			return
		}
	}
	t.Fatal("background refresh never updated the cache")
}

func TestUnknownVerdictIsNotCached(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		return &model.Domain{Verdict: model.VerdictUnknown}, nil, nil
	}}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)

	if _, err := svc.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	// Caching "unknown" would pin a transient failure for the whole TTL.
	if got := fake.count.Load(); got != 2 {
		t.Fatalf("upstream called %d times, want 2 (unknown must not be cached)", got)
	}
}

func TestInvalidDomainRejectedBeforeAnyWork(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		t.Fatal("upstream must not be called for invalid input")
		return nil, nil, nil
	}}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)
	if _, err := svc.Lookup(context.Background(), "not a domain"); err == nil {
		t.Fatal("expected an error for invalid input")
	}
	if got := fake.count.Load(); got != 0 {
		t.Fatalf("upstream called %d times for invalid input", got)
	}
}

// Cache metrics are the only signal an operator has that caching works at all.
// Get() used to have no hit/miss counters wired up, so /api/v1/status always
// reported zero hits even on a fully warm cache.
func TestCacheMetricsReflectHitsAndStaleServing(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		return &model.Domain{Verdict: model.VerdictRegistered, Registrar: "R"}, nil, nil
	}}
	svc := newTestService(t, fake, 40*time.Millisecond, 40*time.Millisecond, time.Hour)

	if _, err := svc.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, metrics := svc.Stats(); metrics.Hits < 1 {
		t.Fatalf("hits = %d after a warm lookup, want >= 1", metrics.Hits)
	}

	time.Sleep(80 * time.Millisecond) // entry is now stale, still servable
	res, err := svc.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Meta.Stale {
		t.Fatal("expected a stale-while-revalidate response")
	}
	if _, metrics := svc.Stats(); metrics.StaleHits < 1 {
		t.Fatalf("stale_hits = %d, want >= 1", metrics.StaleHits)
	}
}

// Asking for ?fresh=1 means "do not use the cache". Reading an entry only to
// discard it still counted as a hit, so the status endpoint reported hits for
// answers that were by definition not served from cache — a number an operator
// would read as "the cache is doing its job".
func TestBypassingTheCacheDoesNotCountAsAHit(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		return &model.Domain{Verdict: model.VerdictRegistered, Registrar: "R"}, nil, nil
	}}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)

	if _, err := svc.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	_, before := svc.Stats()
	for i := 0; i < 3; i++ {
		if _, err := svc.LookupFresh(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	_, after := svc.Stats()
	if after.Hits != before.Hits {
		t.Fatalf("hits went %d -> %d after three cache-bypassing lookups", before.Hits, after.Hits)
	}
	if after.Writes <= before.Writes {
		t.Fatalf("bypassing lookups should still refresh the entry (writes %d -> %d)", before.Writes, after.Writes)
	}
}

// Same question, same answer, whether or not the entry is warm. The cache is an
// implementation detail; it must not be observable in the response body.
func TestColdAndWarmAnswersAgree(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		live := true
		return &model.Domain{
			Verdict: model.VerdictRegistered, Confidence: model.ConfidenceStrong,
			Source: model.SourceRDAP, Registrar: "R", DNSResolves: &live,
		}, nil, nil
	}}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)

	cold, err := svc.Lookup(context.Background(), "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	warm, err := svc.Lookup(context.Background(), "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !warm.Meta.Cached {
		t.Fatal("second lookup should be a cache hit")
	}
	if cold.Domain.Name != warm.Domain.Name || cold.Domain.Verdict != warm.Domain.Verdict {
		t.Fatalf("name/verdict changed with cache state: cold %q/%q vs warm %q/%q",
			cold.Domain.Name, cold.Domain.Verdict, warm.Domain.Name, warm.Domain.Verdict)
	}
	if codesOf(cold.Domain.Alerts) != codesOf(warm.Domain.Alerts) {
		t.Fatalf("alerts changed with cache state: cold %s vs warm %s",
			codesOf(cold.Domain.Alerts), codesOf(warm.Domain.Alerts))
	}
	if cold.Domain.Confidence != warm.Domain.Confidence {
		t.Fatalf("confidence changed with cache state: %d vs %d", cold.Domain.Confidence, warm.Domain.Confidence)
	}
}

func codesOf(alerts []model.Notice) string {
	out := make([]string, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, a.Code)
	}
	return strings.Join(out, ",")
}

// Whichever name fills the cache entry, every later caller must see its own.
// This is the cross-name version of the test above: a subdomain warms the
// entry, then the parent asks, and the parent must not be told it is the
// subdomain.
func TestParentLookupAfterSubdomainDoesNotInheritItsName(t *testing.T) {
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []model.Notice) {
		return &model.Domain{Verdict: model.VerdictRegistered, Confidence: model.ConfidenceStrong, Source: model.SourceRDAP}, nil, nil
	}}
	svc := newTestService(t, fake, time.Minute, time.Minute, time.Hour)

	sub, err := svc.Lookup(context.Background(), "deep.sub.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Domain.Name != "deep.sub.example.org" || sub.Domain.SubdomainOf != "example.org" {
		t.Fatalf("subdomain view = name %q, subdomain_of %q", sub.Domain.Name, sub.Domain.SubdomainOf)
	}

	parent, err := svc.Lookup(context.Background(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !parent.Meta.Cached {
		t.Fatal("the parent should reuse the entry the subdomain filled")
	}
	if parent.Domain.Name != "example.org" {
		t.Fatalf("parent view name = %q, want example.org", parent.Domain.Name)
	}
	if parent.Domain.SubdomainOf != "" {
		t.Fatalf("parent view inherited subdomain_of = %q", parent.Domain.SubdomainOf)
	}
	if got := fake.count.Load(); got != 1 {
		t.Fatalf("upstream called %d times, want 1", got)
	}
}
