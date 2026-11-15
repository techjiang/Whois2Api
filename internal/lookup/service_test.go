package lookup

import (
	"context"
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
	reply func(name string) (*model.Domain, []model.ChannelTiming, []string)
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

func (f *fakeResolver) lookup(ctx context.Context, t *Target) (*model.Domain, []model.ChannelTiming, []string, error) {
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
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []string) {
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
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []string) {
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
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []string) {
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
			if len(a) > 0 {
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
		reply: func(string) (*model.Domain, []model.ChannelTiming, []string) {
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
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []string) {
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
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []string) {
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
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []string) {
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
	fake := &fakeResolver{reply: func(string) (*model.Domain, []model.ChannelTiming, []string) {
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
