package lookup

import (
	"testing"

	"github.com/asoe/whois2api/internal/model"
)

func availableDomain() *model.Domain {
	return &model.Domain{
		Name:    "free-example.com",
		Verdict: model.VerdictAvailable,
		Source:  model.SourceRDAP,
		Raw:     "No match for \"FREE-EXAMPLE.COM\".",
	}
}

func subdomainTarget() *Target {
	return &Target{
		Input:       "www.free-example.com",
		ASCII:       "www.free-example.com",
		Query:       "free-example.com",
		SubdomainOf: "free-example.com",
	}
}

// The subdomain rewrite is a view concern. If it happened in the engine, the
// "registered" verdict would be written into the entry shared with the parent,
// and the next lookup of the parent would report a for-sale name as taken.
func TestSubdomainRewriteStaysInTheView(t *testing.T) {
	engineResult := availableDomain() // exactly what resolve() returns

	stored := storageView(engineResult, &Target{Input: "free-example.com", ASCII: "free-example.com", Query: "free-example.com"})
	if stored.Verdict != model.VerdictAvailable {
		t.Fatalf("stored verdict = %q, want available (the parent really is free)", stored.Verdict)
	}

	view := present(stored, subdomainTarget())
	if view.Verdict != model.VerdictRegistered {
		t.Fatalf("subdomain view verdict = %q, want registered", view.Verdict)
	}
	if len(view.Alerts) == 0 {
		t.Fatal("subdomain view should explain the rewrite")
	}

	// And the parent's own view must still say available.
	parent := present(stored, &Target{Input: "free-example.com", ASCII: "free-example.com", Query: "free-example.com"})
	if parent.Verdict != model.VerdictAvailable {
		t.Fatalf("parent view verdict = %q, want available", parent.Verdict)
	}
}

func TestPresentDoesNotMutateItsInput(t *testing.T) {
	src := availableDomain()
	_ = present(src, subdomainTarget())
	if src.Verdict != model.VerdictAvailable {
		t.Fatal("present() mutated the shared/cached domain")
	}
}

func TestStorageViewDropsPerRequestFields(t *testing.T) {
	target := &Target{Input: "example.com", ASCII: "example.com", Query: "example.com"}
	d := present(availableDomain(), target)
	d.DaysUntilExpiry = intPtr(3)
	d.Alerts = []model.Notice{{Code: "x", Text: "a"}}

	stored := storageView(d, target)
	if stored.Raw != "" {
		t.Errorf("raw payload must not be cached, got %q", stored.Raw)
	}
	if stored.Input != "" || stored.QueryTarget != "" {
		t.Errorf("per-request fields leaked into storage: input=%q target=%q", stored.Input, stored.QueryTarget)
	}
	if stored.DaysUntilExpiry != nil {
		t.Error("expiry countdown must be recomputed per request, not cached")
	}
	if d.Raw == "" || len(d.Alerts) == 0 {
		t.Error("storageView mutated the domain it was given")
	}
}

func intPtr(v int) *int { return &v }

// A cached entry is about the registrable domain, and it was named by whichever
// query happens to have filled it. Echoing that name back means a parent starts
// being labelled with a subdomain nobody asked about — the exact "answer depends
// on who asked first" failure the cache is supposed to be invisible to.
func TestPresentAlwaysEchoesTheCallersName(t *testing.T) {
	// The entry as it was stored by a subdomain query.
	stored := storageView(
		&model.Domain{Name: "deep.sub.example.org", Verdict: model.VerdictRegistered, Source: model.SourceRDAP},
		&Target{Input: "deep.sub.example.org", ASCII: "deep.sub.example.org", Query: "example.org", SubdomainOf: "example.org"},
	)
	if stored.Name != "example.org" {
		t.Fatalf("stored name = %q, want the registrable domain", stored.Name)
	}
	parent := present(stored, &Target{Input: "example.org", ASCII: "example.org", Query: "example.org"})
	if parent.Name != "example.org" {
		t.Fatalf("parent view name = %q, want example.org", parent.Name)
	}
	if parent.SubdomainOf != "" || parent.Input != "example.org" {
		t.Fatalf("per-request fields leaked from the entry: %+v", parent)
	}
}

// Alerts fall into two kinds: what the registry said, and what this particular
// request measured. Only the first kind belongs in the cache. Keeping the
// second made a warm answer quietly drop caveats a cold one reported — same
// domain, same registry record, different warnings depending on cache state.
func TestStorageViewKeepsOnlyRegistryAlerts(t *testing.T) {
	d := &model.Domain{
		Name:    "webvan.example",
		Verdict: model.VerdictRegistered,
		Alerts: []model.Notice{
			model.NoticeRegistryWithheld,         // registry fact
			model.NoticeRegisteredWithoutDNS,     // DNS probe from request time
			model.NoticeExpiresWithin30Days,      // countdown from request time
			model.NoticeSubdomainParentAvailable, // per-request rewrite
		},
	}
	stored := storageView(d, &Target{Input: "webvan.example", ASCII: "webvan.example", Query: "webvan.example"})
	if len(stored.Alerts) != 1 || stored.Alerts[0].Code != model.NoticeRegistryWithheld.Code {
		t.Fatalf("stored alerts = %+v, want only the registry fact", stored.Alerts)
	}

	// The warm view must still report the DNS caveat, re-derived from the probe.
	stored.DNSResolves = boolPtr(false)
	warm := present(stored, &Target{Input: "webvan.example", ASCII: "webvan.example", Query: "webvan.example"})
	if !hasCode(warm.Alerts, model.NoticeRegisteredWithoutDNS.Code) {
		t.Fatalf("warm view lost the DNS caveat: %+v", warm.Alerts)
	}
}

// The DNS probe measures the registrable domain because the cache entry is
// about the registrable domain. Measuring the caller's name instead meant one
// query for a dead subdomain cached "no DNS" for its live parent.
func TestDNSProbeIsStoredForTheRegistrableDomain(t *testing.T) {
	live := boolPtr(true)
	stored := storageView(
		&model.Domain{Name: "www.example.org", Verdict: model.VerdictRegistered, DNSResolves: live, Source: model.SourceRDAP},
		&Target{Input: "www.example.org", ASCII: "www.example.org", Query: "example.org", SubdomainOf: "example.org"},
	)
	if stored.DNSResolves == nil || !*stored.DNSResolves {
		t.Fatal("the parent's DNS answer must survive a subdomain query")
	}
}

func boolPtr(v bool) *bool { return &v }

func hasCode(alerts []model.Notice, code string) bool {
	for _, a := range alerts {
		if a.Code == code {
			return true
		}
	}
	return false
}
