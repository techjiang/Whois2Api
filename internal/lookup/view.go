package lookup

import (
	"time"

	"github.com/asoe/whois2api/internal/model"
	"github.com/asoe/whois2api/internal/parse"
)

// viewAlertCodes are the caveats that describe *this request* rather than the
// registry record: they depend on which name the caller asked about (a
// subdomain) or on a measurement taken at request time (the DNS probe, the
// expiry countdown). The cache holds only what the registry said; these are
// re-derived on every request, so a warm answer says the same things a cold one
// does.
var viewAlertCodes = map[string]struct{}{
	model.NoticeSubdomainParentAvailable.Code: {},
	model.NoticeExpired.Code:                  {},
	model.NoticeExpiresWithin7Days.Code:       {},
	model.NoticeExpiresWithin30Days.Code:      {},
	model.NoticeRegisteredWithoutDNS.Code:     {},
	model.NoticeDNSResolvesButAvailable.Code:  {},
	model.NoticeUnknownButDNS.Code:            {},
}

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

	// The stored record describes the registrable domain, so a cached entry
	// carries the name of whichever query happened to fill it. Reporting that
	// name to a later caller means answering with a name nobody asked for —
	// query a subdomain once, and the parent starts coming back labelled as the
	// subdomain. Always echo the caller's name, exactly like a cold lookup.
	if t.ASCII != "" {
		out.Name = t.ASCII
	}
	out.Input = t.Input
	out.QueryTarget = t.Query
	out.SubdomainOf = t.SubdomainOf
	out.Unicode = displayName(t.Input, t.ASCII)

	// Re-derive the DNS caveats from the stored probe instead of trusting the
	// alerts the engine happened to compute when it filled the entry. This runs
	// before the subdomain rewrite below so the signals describe the registry's
	// verdict about the registrable domain, which is what the probe measured.
	if out.DNSResolves != nil {
		alerts, confidence := dnsSignals(out, *out.DNSResolves, nil)
		out.Alerts = mergeAlerts(out.Alerts, alerts)
		if confidence != nil {
			out.Confidence = *confidence
		}
	}

	// A cached "available" for the parent must never be shown as available for
	// a subdomain: you cannot register www.example.com even when example.com is
	// free. This rewrite belongs here, in the per-request view — doing it in the
	// engine would write a "registered" verdict into the cache entry shared with
	// the (genuinely available) parent.
	if out.Verdict == model.VerdictAvailable && t.SubdomainOf != "" {
		out.Verdict = model.VerdictRegistered
		out.Confidence = model.ConfidenceGood
		out.Alerts = append(out.Alerts, model.NoticeSubdomainParentAvailable)
	}

	// Recompute time-relative fields at read time.
	out.DaysUntilExpiry = parse.DaysUntil(out.ExpiresAt)
	out.Alerts = mergeAlerts(out.Alerts, expiryAlerts(out))
	return out
}

// storageView strips per-request fields before an entry is written, so the
// on-disk record is reusable for any name inside the registrable domain.
func storageView(d *model.Domain, t *Target) *model.Domain {
	out := d.Clone()
	if out == nil {
		return nil
	}
	// The entry is about t.Query, so that is the name it stores. Every read
	// overwrites it with the caller's own name.
	out.Name = t.Query
	out.Input = ""
	out.QueryTarget = ""
	out.SubdomainOf = ""
	out.Unicode = ""
	out.DaysUntilExpiry = nil
	out.Alerts = registryAlerts(d.Alerts)
	// The upstream payload is a per-request debugging aid. Caching it would
	// multiply every entry's size for a field almost nobody asks for.
	out.Raw = ""
	return out
}

// registryAlerts keeps the caveats that are part of the registry's answer.
func registryAlerts(alerts []model.Notice) []model.Notice {
	var out []model.Notice
	for _, a := range alerts {
		if _, perRequest := viewAlertCodes[a.Code]; perRequest {
			continue
		}
		out = append(out, a)
	}
	return out
}

// mergeAlerts appends alerts without duplicating codes.
func mergeAlerts(existing []model.Notice, extra []model.Notice) []model.Notice {
	if len(extra) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing))
	for _, a := range existing {
		seen[a.Code] = struct{}{}
	}
	for _, a := range extra {
		if _, ok := seen[a.Code]; ok {
			continue
		}
		seen[a.Code] = struct{}{}
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
