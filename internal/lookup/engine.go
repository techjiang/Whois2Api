// Package lookup orchestrates a single domain lookup: normalization, route
// resolution, concurrent RDAP/WHOIS racing, cache interaction and verdict
// synthesis.
package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/techjiang/Whois2Api/internal/model"
	"github.com/techjiang/Whois2Api/internal/parse"
	"github.com/techjiang/Whois2Api/internal/tld"
	"github.com/techjiang/Whois2Api/internal/upstream"
)

// ErrInvalidDomain is returned for input that is not a domain name.
var ErrInvalidDomain = errors.New("invalid domain name")

// ErrUnsupportedTLD is returned when no machine-readable service exists for the
// TLD, or the TLD is unknown.
var ErrUnsupportedTLD = errors.New("unsupported top-level domain")

// Options configures the engine.
type Options struct {
	RDAPTimeout  time.Duration
	WhoIsTimeout time.Duration
	TotalTimeout time.Duration
	// PreferWhoIs flips which channel is consulted first when only one runs.
	PreferWhoIs bool
	// RDAPOnly disables the WHOIS fallback.
	RDAPOnly bool
	// ResolveDNS enables the DNS corroboration signal.
	ResolveDNS bool
}

// Engine performs lookups. It is safe for concurrent use.
type Engine struct {
	psl    *tld.List
	table  *tld.Table
	rdap   *upstream.RDAPClient
	whois  *upstream.WhoIsClient
	opts   Options
	resolv *net.Resolver
}

// New builds an engine.
func New(psl *tld.List, table *tld.Table, opts Options) *Engine {
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 12 * time.Second
	}
	return &Engine{
		psl:   psl,
		table: table,
		rdap:  upstream.NewRDAPClient(opts.RDAPTimeout),
		whois: upstream.NewWhoIsClient(opts.WhoIsTimeout),
		opts:  opts,
		resolv: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, network, address)
			},
		},
	}
}

// Target is a normalized lookup target.
type Target struct {
	// Input is what the caller asked for, trimmed.
	Input string
	// ASCII is the normalized, punycode form of Input.
	ASCII string
	// Query is the registrable domain actually sent upstream.
	Query string
	// SubdomainOf is the registrable domain when Input was deeper.
	SubdomainOf string
	// TLD is the ASCII top-level label.
	TLD string
	// Suffix is the public suffix of Query.
	Suffix string
	// Registrable is the eTLD+1 of Input.
	Registrable string
	// PrivateSuffix is set when the name sits strictly below a PRIVATE-section
	// public suffix (github.io, uk.com, s3.amazonaws.com). Those suffixes are
	// handed out by a vendor, not by the TLD registry, so the registry has no
	// record of the name and its "no match" is not an answer.
	PrivateSuffix bool
}

// Prepare normalizes user input and decides what to ask upstream.
func (e *Engine) Prepare(input string) (*Target, error) {
	ascii, err := tld.Normalize(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, strings.TrimSpace(input))
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return nil, fmt.Errorf("%w: %q has no top-level domain", ErrInvalidDomain, input)
	}
	t := &Target{Input: strings.TrimSpace(input), ASCII: ascii, TLD: labels[len(labels)-1]}

	suffix := e.psl.PublicSuffix(ascii)
	if suffix == "" {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, input)
	}
	t.Suffix = suffix
	registrable := e.psl.RegistrableDomain(ascii)
	if registrable == "" {
		// The name is itself a public suffix. That is not an error: multi-label
		// suffixes such as "github.io" or "co.uk" really do have registry
		// records, and a single-label TLD like "com" was already rejected
		// above. Ask the registry for the name as typed and let it answer.
		t.Registrable = ascii
		t.Query = ascii
		return t, nil
	}
	t.Registrable = registrable
	t.Query = registrable
	if !strings.EqualFold(registrable, ascii) {
		t.SubdomainOf = registrable
	}
	// The route must be resolved from the *queried* name's TLD, which can
	// differ from the input's TLD for multi-label suffixes like "github.io".
	queryLabels := strings.Split(registrable, ".")
	t.TLD = queryLabels[len(queryLabels)-1]
	// A name strictly below a vendor-managed suffix is invisible to the TLD
	// registry. Note the strictness: the suffix itself (github.io, uk.com) does
	// have a registry record and must be queried normally.
	t.PrivateSuffix = e.psl.IsPrivateSuffix(suffix) && !strings.EqualFold(registrable, suffix)
	return t, nil
}

// Route resolves the upstream endpoints for a target.
func (e *Engine) Route(t *Target) (tld.Route, error) {
	route, ok := e.table.Lookup(t.TLD)
	if !ok {
		return tld.Route{}, fmt.Errorf("%w: .%s", ErrUnsupportedTLD, t.TLD)
	}
	if route.WhoIs == "" && len(route.RDAP) == 0 {
		// Delegated but with no public WHOIS or RDAP service (e.g. .gr, .mil).
		// Saying so plainly is better than a generic error.
		return tld.Route{}, fmt.Errorf("%w: .%s publishes no public WHOIS or RDAP service", ErrUnsupportedTLD, t.TLD)
	}
	return route, nil
}

// Lookup performs the full resolution for a target and returns a populated
// model.Domain plus channel timings. The returned error is only for failures
// that prevent any answer (invalid input, unsupported TLD).
func (e *Engine) Lookup(ctx context.Context, t *Target) (*model.Domain, []model.ChannelTiming, []model.Notice, error) {
	route, err := e.Route(t)
	if err != nil {
		return nil, nil, nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, e.opts.TotalTimeout)
	defer cancel()

	domain := &model.Domain{
		Name:        t.ASCII,
		Input:       t.Input,
		QueryTarget: t.Query,
		SubdomainOf: t.SubdomainOf,
		TLD:         t.TLD,
		Suffix:      t.Suffix,
		Registrable: t.Registrable,
	}
	domain.Unicode = displayName(t.Input, t.ASCII)

	var warnings []model.Notice
	timings, primary := e.race(ctx, route, t.Query)

	applyChannel(domain, primary)

	// Subdomain handling deliberately lives in present(), not here. This
	// result is what gets cached under the registrable domain's key, and a
	// per-request rewrite would poison that shared entry.

	// Corroborate with DNS. This never overrides an authoritative answer; it
	// only adds evidence when the registries gave us nothing usable, or
	// flags the (rare) case where DNS says a name exists but the registry
	// said it was free.
	if e.opts.ResolveDNS {
		// Probe the registrable domain, not the caller's exact name. The probe
		// is stored with the cache entry, and the entry belongs to t.Query: a
		// subdomain's A records say nothing about whether the registrable
		// domain is registered, and probing them meant one query for a dead
		// subdomain could cache "no DNS" for a perfectly live parent.
		if resolves, dnsErr := e.dnsResolves(ctx, t.Query); dnsErr == nil {
			domain.DNSResolves = &resolves
			domain = reconcileDNS(domain, resolves, &warnings)
		}
	}

	domain.DaysUntilExpiry = parse.DaysUntil(domain.ExpiresAt)
	domain.Alerts = append(domain.Alerts, expiryAlerts(domain)...)
	return domain, timings, warnings, nil
}

// displayName returns a human-readable form of the input when it differs from
// the ASCII name (IDN input, or punycode input shown in its native script).
func displayName(input, ascii string) string {
	trimmed := strings.Trim(strings.ToLower(strings.TrimSpace(input)), ".")
	if trimmed == ascii {
		return ""
	}
	if !isASCII(trimmed) {
		return trimmed
	}
	return toUnicode(trimmed)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// dnsResolves reports whether the name has A/AAAA records. A NXDOMAIN-style
// answer is a normal "false", not an error.
func (e *Engine) dnsResolves(ctx context.Context, name string) (bool, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := e.resolv.LookupHost(lookupCtx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || dnsErr.IsTemporary) {
			return false, nil
		}
		return false, err
	}
	return len(addrs) > 0, nil
}
