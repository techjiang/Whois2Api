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

	stored := storageView(engineResult)
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

	stored := storageView(d)
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
