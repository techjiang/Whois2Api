// Package model defines the wire types shared by the lookup engine and API.
package model

import "time"

// Verdict is the three-state answer for a domain.
//
// The third state is the whole point: a registry that rate-limits us, times
// out, or answers with garbage has NOT told us the domain is free. Collapsing
// that into "available" is the single most common bug in self-hosted WHOIS
// APIs, and it produces confidently wrong answers. We refuse to guess.
type Verdict string

const (
	// VerdictRegistered means an authoritative record was found.
	VerdictRegistered Verdict = "registered"
	// VerdictAvailable means an authoritative server explicitly said "no such
	// object". This is a positive statement, not an absence of one.
	VerdictAvailable Verdict = "available"
	// VerdictUnknown means we could not get an authoritative answer.
	VerdictUnknown Verdict = "unknown"
)

// Confidence is a 0-100 score for how much the verdict can be trusted.
type Confidence int

const (
	// ConfidenceNone is used when no channel produced a usable answer.
	ConfidenceNone Confidence = 0
	// ConfidenceWeak means only a soft signal (e.g. DNS absence) supported it.
	ConfidenceWeak Confidence = 35
	// ConfidenceGood means one authoritative protocol gave a clear answer.
	ConfidenceGood Confidence = 80
	// ConfidenceStrong means both channels agreed, or RDAP was definitive.
	ConfidenceStrong Confidence = 95
)

// Source names the channel that produced the winning answer.
type Source string

const (
	SourceRDAP  Source = "rdap"
	SourceWhoIs Source = "whois"
	SourceDNS   Source = "dns"
	SourceCache Source = "cache"
)

// Notice is a machine-readable caveat attached to a result.
//
// Code is the contract: it never changes, and clients localise on it. Text is
// the canonical English rendering, used when a client has no translation for
// that code. Keeping both is what makes the UI translatable without asking it
// to pattern-match English prose: prose changes, codes do not, and an unknown
// code degrades to readable English instead of an empty line.
type Notice struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

// Notice codes. Adding one is a compatible change; renaming one is not.
//
// The codes deliberately carry no human wording: "rate_limited" survives a copy
// edit, "Upstream registry rate-limited this query" does not.
var (
	NoticeRegistryWithheld = Notice{Code: "registry_withheld",
		Text: "Registry withholds this record (usage restrictions) but confirms the name exists."}
	NoticeRateLimited = Notice{Code: "rate_limited",
		Text: "Upstream registry rate-limited this query; retry shortly."}
	NoticeBlocked = Notice{Code: "blocked",
		Text: "Upstream registry refused this query (access policy)."}
	NoticeDNSResolvesButAvailable = Notice{Code: "dns_resolves_but_available",
		Text: "The name resolves over DNS even though the registry reports it as available; usually wildcard DNS or a lagging registry."}
	NoticeRegisteredWithoutDNS = Notice{Code: "registered_without_dns",
		Text: "Registered but currently has no address records (parked or not yet configured)."}
	NoticeUnknownButDNS = Notice{Code: "unknown_but_dns",
		Text: "No definitive registry answer, but the name resolves over DNS, so it is almost certainly registered."}
	NoticePrivateSuffix = Notice{Code: "private_suffix_delegated",
		Text: "This name is delegated by the operator of a private public suffix (such as github.io or uk.com); the TLD registry has no record of it, so its answer is not evidence about availability."}
	NoticeSubdomainParentAvailable = Notice{Code: "subdomain_parent_available",
		Text: "This is a subdomain; only its registrable domain can be registered."}
	NoticeExpired = Notice{Code: "expired",
		Text: "Registration has expired according to the registry."}
	NoticeExpiresWithin7Days = Notice{Code: "expires_within_7_days",
		Text: "Expires within 7 days; renewal is urgent."}
	NoticeExpiresWithin30Days = Notice{Code: "expires_within_30_days",
		Text: "Expires within 30 days."}

	WarningStaleServed = Notice{Code: "stale_served",
		Text: "Served from cache while a background refresh runs."}
	WarningNoAnswerNoDNS = Notice{Code: "no_answer_no_dns",
		Text: "No definitive registry answer and DNS has no records; availability is unconfirmed."}
	WarningCachedWithoutRaw = Notice{Code: "cached_without_raw",
		Text: "Cached answers carry no raw payload; add ?fresh=1 to query the registry again."}
	WarningNoUpstreamPayload = Notice{Code: "no_upstream_payload",
		Text: "This answer carried no upstream payload."}
)

// Status is an EPP/registry status entry with its canonical URL when known.
type Status struct {
	Code string `json:"code"`
	URL  string `json:"url,omitempty"`
}

// Contact is a partially-redacted party attached to a registration.
type Contact struct {
	Role  string `json:"role"`
	Name  string `json:"name,omitempty"`
	Org   string `json:"org,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// Domain is the normalized, structured result of a lookup.
type Domain struct {
	// Name is the ASCII/punycode form used for queries.
	Name string `json:"name"`
	// Unicode is set only when the input was an internationalized name.
	Unicode string `json:"unicode,omitempty"`
	// TLD is the ASCII top-level label, e.g. "com" or "xn--fiqs8s".
	TLD string `json:"tld"`
	// Suffix is the public suffix, e.g. "co.uk" or "github.io".
	Suffix string `json:"suffix"`
	// Registrable is the eTLD+1, e.g. "example.co.uk".
	Registrable string `json:"registrable"`

	Verdict    Verdict    `json:"status"`
	Confidence Confidence `json:"confidence"`
	Source     Source     `json:"source,omitempty"`

	Registrar       string     `json:"registrar,omitempty"`
	RegistrarID     string     `json:"registrar_id,omitempty"`
	RegistrarURL    string     `json:"registrar_url,omitempty"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	DaysUntilExpiry *int       `json:"days_until_expiry,omitempty"`
	Statuses        []Status   `json:"statuses,omitempty"`
	NameServers     []string   `json:"name_servers,omitempty"`
	DNSSEC          string     `json:"dnssec,omitempty"`
	Contacts        []Contact  `json:"contacts,omitempty"`
	RegistryID      string     `json:"registry_id,omitempty"`

	// Input is the name exactly as the caller supplied it.
	Input string `json:"input,omitempty"`
	// QueryTarget is the name actually sent upstream. When the input was a
	// subdomain this is its registrable parent, because registries only answer
	// for the eTLD+1. Reporting a subdomain as "available" would be wrong:
	// you cannot register www.google.com.
	QueryTarget string `json:"query_target,omitempty"`
	// SubdomainOf is set when the input was deeper than the registrable domain.
	SubdomainOf string `json:"subdomain_of,omitempty"`

	// DNSResolves reports whether the registrable domain had address records at
	// lookup time. It is a corroborating signal only, never a verdict by
	// itself, and it is a point-in-time measurement rather than registry data.
	// The probe targets the registrable domain because that is what the cache
	// entry describes: probing the caller's subdomain instead made the same
	// entry mean different things depending on who filled it.
	DNSResolves *bool `json:"dns_resolves,omitempty"`

	// Alerts are risk hints derived from the fields above. Each carries a
	// stable code so a client can render it in its own language.
	Alerts []Notice `json:"alerts,omitempty"`

	// Raw is the unparsed upstream payload, included only when requested.
	Raw string `json:"raw,omitempty"`
}

// ChannelTiming records how one upstream channel performed.
type ChannelTiming struct {
	Channel  Source `json:"channel"`
	Millis   int64  `json:"ms"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
}

// Meta describes how a result was produced.
type Meta struct {
	// Cached reports whether the body came from the embedded cache.
	Cached bool `json:"cached"`
	// Stale reports a cached body served while a refresh runs.
	Stale bool `json:"stale"`
	// CacheAgeSeconds is how old the cached entry was.
	CacheAgeSeconds int64 `json:"cache_age_seconds,omitempty"`
	// TotalMillis is the wall-clock cost of the lookup.
	TotalMillis int64 `json:"total_ms"`
	// Channels lists per-channel timings and failures.
	Channels []ChannelTiming `json:"channels,omitempty"`
	// TableSource names the route table in use.
	TableSource string `json:"table_source,omitempty"`
	// Warnings are non-fatal caveats for the caller, coded like Alerts.
	Warnings []Notice `json:"warnings,omitempty"`
}

// Clone returns a deep copy so callers can safely adapt a shared or cached
// value without racing other requests.
func (d *Domain) Clone() *Domain {
	if d == nil {
		return nil
	}
	cp := *d
	if d.CreatedAt != nil {
		t := *d.CreatedAt
		cp.CreatedAt = &t
	}
	if d.UpdatedAt != nil {
		t := *d.UpdatedAt
		cp.UpdatedAt = &t
	}
	if d.ExpiresAt != nil {
		t := *d.ExpiresAt
		cp.ExpiresAt = &t
	}
	if d.DaysUntilExpiry != nil {
		v := *d.DaysUntilExpiry
		cp.DaysUntilExpiry = &v
	}
	if d.DNSResolves != nil {
		v := *d.DNSResolves
		cp.DNSResolves = &v
	}
	if d.Statuses != nil {
		cp.Statuses = make([]Status, len(d.Statuses))
		copy(cp.Statuses, d.Statuses)
	}
	if d.NameServers != nil {
		cp.NameServers = make([]string, len(d.NameServers))
		copy(cp.NameServers, d.NameServers)
	}
	if d.Contacts != nil {
		cp.Contacts = make([]Contact, len(d.Contacts))
		copy(cp.Contacts, d.Contacts)
	}
	if d.Alerts != nil {
		cp.Alerts = make([]Notice, len(d.Alerts))
		copy(cp.Alerts, d.Alerts)
	}
	return &cp
}

// Result bundles a Domain with its lookup metadata.
type Result struct {
	Domain *Domain `json:"domain"`
	Meta   Meta    `json:"meta"`
}

// BatchItem is one entry in a batch response.
type BatchItem struct {
	Query  string  `json:"query"`
	Domain *Domain `json:"domain,omitempty"`
	Meta   Meta    `json:"meta,omitempty"`
	Error  string  `json:"error,omitempty"`
}
