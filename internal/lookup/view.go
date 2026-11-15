package lookup

import (
	"fmt"
	"time"

	"github.com/asoe/whois2api/internal/model"
	"github.com/asoe/whois2api/internal/parse"
)

// present adapts a freshly-resolved (and therefore un-normalized-for-this-
// request) domain to the exact name the caller asked for.
//
// This exists because the cache is keyed by registrable domain: a query for
// "www.example.com" and "example.com" share one upstream result, but must not
// share a view. It also re-derives time-relative fields, which would otherwise
// freeze at cache-write time.
func present(d *model.Domain, t *Target) *model.Domain {
	out := d.Clone()
	if out == nil {
		return nil
	}

	out.Input = t.Input
	out.QueryTarget = t.Query
	out.SubdomainOf = t.SubdomainOf
	out.Unicode = displayName(t.Input, t.ASCII)

	// A cached "available" for the parent must never be shown for a subdomain:
	// you cannot register www.example.com even when example.com is free.
	if out.Verdict == model.VerdictAvailable && t.SubdomainOf != "" {
		out.Alerts = append(out.Alerts,
			fmt.Sprintf("%s is a subdomain of %s; registries report only the registrable domain.", t.ASCII, t.SubdomainOf))
	}

	// Recompute time-relative fields at read time.
	out.DaysUntilExpiry = parse.DaysUntil(out.ExpiresAt)
	out.Alerts = mergeAlerts(out.Alerts, expiryAlerts(out))
	return out
}

// storageView strips per-request fields before an entry is written, so the
// on-disk record is reusable for any name inside the registrable domain.
func storageView(d *model.Domain) *model.Domain {
	out := d.Clone()
	if out == nil {
		return nil
	}
	out.Input = ""
	out.QueryTarget = ""
	out.SubdomainOf = ""
	out.Unicode = ""
	out.DaysUntilExpiry = nil
	out.Alerts = nil
	return out
}

// mergeAlerts appends alerts without duplicating strings.
func mergeAlerts(existing []string, extra []string) []string {
	if len(extra) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing))
	for _, a := range existing {
		seen[a] = struct{}{}
	}
	for _, a := range extra {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		existing = append(existing, a)
	}
	return existing
}

// ageSeconds is a small helper for metadata.
func ageSeconds(t time.Time) int64 {
	d := time.Since(t)
	if d < 0 {
		return 0
	}
	return int64(d.Seconds())
}
