package lookup

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/techjiang/Whois2Api/internal/model"
	"github.com/techjiang/Whois2Api/internal/parse"
	"github.com/techjiang/Whois2Api/internal/tld"
	"golang.org/x/net/idna"
)

// corroborationGrace is how long we keep listening for the second protocol
// after one has already produced a definitive answer. Registries that answer in
// 200ms therefore reply in ~200ms, while a fast-but-wrong channel still gets a
// chance to be corrected by the slower authoritative one.
const corroborationGrace = 300 * time.Millisecond

// channelResult carries one protocol's answer.
type channelResult struct {
	source     model.Source
	verdict    parse.Outcome
	evidence   string
	millis     int64
	parsed     parse.Parsed
	contacts   []parse.Contact
	secureDNS  string
	registryID string
	raw        string
	err        error
}

// race queries RDAP and WHOIS concurrently and returns the best answer found
// plus per-channel timings.
//
// The early-return rule is the performance story: as soon as one channel gives
// a definitive answer we stop waiting for a slow sibling, after a short grace
// window that still allows corroboration. Registries that are fast stay fast;
// broken ones cannot hold the request hostage until the total timeout.
func (e *Engine) race(ctx context.Context, route tld.Route, domain string) ([]model.ChannelTiming, channelResult) {
	type slot struct{ res channelResult }

	// Buffer equals the number of launched goroutines so no sender ever blocks
	// after we return early: that is what prevents goroutine leaks.
	ch := make(chan slot, 2)
	var wg sync.WaitGroup

	launchRDAP := len(route.RDAP) > 0
	launchWhoIs := route.WhoIs != "" && !e.opts.RDAPOnly

	if launchRDAP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last channelResult
			for _, base := range route.RDAP {
				resp := e.rdap.Query(ctx, base, domain)
				cr := channelResult{source: model.SourceRDAP, verdict: resp.Result.Verdict, millis: resp.Millis}
				if resp.Err != nil {
					cr.verdict = parse.OutcomeUnusable
					cr.evidence = resp.Err.Error()
					cr.err = resp.Err
					last = cr
					continue
				}
				cr.evidence = resp.Result.Reason
				cr.parsed = resp.Result.Parsed
				cr.contacts = resp.Result.Contacts
				cr.secureDNS = resp.Result.SecureDNS
				cr.registryID = resp.Result.RegistryID
				cr.raw = string(resp.Raw)
				last = cr
				if isUsable(cr.verdict) {
					break
				}
			}
			ch <- slot{res: last}
		}()
	}

	if launchWhoIs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := e.whois.Query(ctx, route.WhoIs, domain)
			cr := channelResult{
				source:   model.SourceWhoIs,
				verdict:  resp.Outcome,
				evidence: resp.Evidence,
				millis:   resp.Millis,
				err:      resp.Err,
				raw:      resp.Raw,
			}
			if resp.Err != nil && resp.Outcome == parse.OutcomeUnusable {
				cr.evidence = resp.Err.Error()
			}
			cr.parsed = parse.ParseWhoIs(resp.Raw)
			ch <- slot{res: cr}
		}()
	}

	expected := 0
	if launchRDAP {
		expected++
	}
	if launchWhoIs {
		expected++
	}

	var collected []channelResult
	if expected == 0 {
		return nil, channelResult{verdict: parse.OutcomeUnusable, evidence: "no upstream channel configured"}
	}

	deadline := time.NewTimer(e.opts.TotalTimeout)
	defer deadline.Stop()
	var graceC <-chan time.Time

collect:
	for len(collected) < expected {
		select {
		case s := <-ch:
			collected = append(collected, s.res)
			if isUsable(s.res.verdict) && graceC == nil {
				// Start the grace window so a slow sibling can still weigh in.
				t := time.NewTimer(corroborationGrace)
				defer t.Stop()
				graceC = t.C
			}
		case <-graceC:
			break collect
		case <-deadline.C:
			break collect
		case <-ctx.Done():
			break collect
		}
	}

	best := choose(collected, e.opts.PreferWhoIs)
	if best.raw == "" {
		// The winning channel gave no payload (an RDAP 404 with an empty body,
		// typically). The debug view is far more useful with the sibling's
		// payload than with nothing.
		for _, c := range collected {
			if c.raw != "" {
				best.raw = c.raw
				break
			}
		}
	}

	timings := make([]model.ChannelTiming, 0, len(collected))
	for _, c := range collected {
		t := model.ChannelTiming{Channel: c.source, Millis: c.millis, OK: isUsable(c.verdict)}
		switch {
		case c.err != nil:
			t.Error = c.err.Error()
		case !isUsable(c.verdict):
			t.Error = c.evidence
		}
		timings = append(timings, t)
	}
	return timings, best
}

// choose picks the best answer by evidentiary strength, not arrival order.
//
// A fast "no such object" from a throttled or misconfigured endpoint must never
// outrank an authoritative record, and a definitive answer always outranks an
// "unknown". Ties break toward RDAP (structured, less likely misparsed), then
// toward the lower latency.
func choose(results []channelResult, preferWhoIs bool) channelResult {
	if len(results) == 0 {
		return channelResult{verdict: parse.OutcomeUnusable, evidence: "no upstream channel answered"}
	}
	rank := func(o parse.Outcome) int {
		switch o {
		case parse.OutcomeFound:
			return 100
		case parse.OutcomeNotFound:
			return 90
		case parse.OutcomeRestricted:
			return 85
		case parse.OutcomeRateLimited, parse.OutcomeBlocked:
			return 10
		default:
			return 0
		}
	}
	better := func(a, b channelResult) bool {
		ra, rb := rank(a.verdict), rank(b.verdict)
		if ra != rb {
			return ra > rb
		}
		preferred := model.SourceRDAP
		if preferWhoIs {
			preferred = model.SourceWhoIs
		}
		if a.source == preferred && b.source != preferred {
			return true
		}
		if b.source == preferred && a.source != preferred {
			return false
		}
		return a.millis < b.millis
	}
	best := results[0]
	for _, r := range results[1:] {
		if better(r, best) {
			best = r
		}
	}
	return best
}

// isUsable reports whether an outcome is a real answer about the domain.
func isUsable(o parse.Outcome) bool {
	switch o {
	case parse.OutcomeFound, parse.OutcomeNotFound, parse.OutcomeRestricted:
		return true
	}
	return false
}

// applyChannel copies a channel answer into the model.
func applyChannel(d *model.Domain, r channelResult) {
	switch r.verdict {
	case parse.OutcomeFound:
		d.Verdict = model.VerdictRegistered
		d.Confidence = model.ConfidenceStrong
	case parse.OutcomeRestricted:
		d.Verdict = model.VerdictRegistered
		d.Confidence = model.ConfidenceGood
		d.Alerts = append(d.Alerts, model.NoticeRegistryWithheld)
	case parse.OutcomeNotFound:
		d.Verdict = model.VerdictAvailable
		d.Confidence = model.ConfidenceStrong
	case parse.OutcomeRateLimited:
		d.Verdict = model.VerdictUnknown
		d.Alerts = append(d.Alerts, model.NoticeRateLimited)
	case parse.OutcomeBlocked:
		d.Verdict = model.VerdictUnknown
		d.Alerts = append(d.Alerts, model.NoticeBlocked)
	default:
		d.Verdict = model.VerdictUnknown
	}
	if isUsable(r.verdict) {
		d.Source = r.source
	}
	// Keep the winning channel's payload for the debug view. The service layer
	// strips it before caching, so this never reaches the database.
	d.Raw = truncateRaw(r.raw)
	if d.Verdict == model.VerdictUnknown {
		return
	}

	p := r.parsed
	if p.Registrar != "" {
		d.Registrar = p.Registrar
	}
	if p.RegistrarID != "" {
		d.RegistrarID = p.RegistrarID
	}
	if p.RegistrarURL != "" {
		d.RegistrarURL = p.RegistrarURL
	}
	if p.RegistryID != "" {
		d.RegistryID = p.RegistryID
	} else if r.registryID != "" {
		d.RegistryID = r.registryID
	}
	if t := parse.ParseDate(p.Created); t != nil {
		d.CreatedAt = t
	}
	if t := parse.ParseDate(p.Updated); t != nil {
		d.UpdatedAt = t
	}
	if t := parse.ParseDate(p.Expires); t != nil {
		d.ExpiresAt = t
	}
	if len(p.NameServers) > 0 {
		d.NameServers = p.NameServers
	}
	d.DNSSEC = firstNonEmpty(r.secureDNS, p.DNSSEC)
	for _, s := range p.Statuses {
		d.Statuses = append(d.Statuses, model.Status{Code: s, URL: eppURL(s)})
	}
	for _, c := range r.contacts {
		d.Contacts = append(d.Contacts, model.Contact{Role: c.Role, Name: c.Name, Org: c.Org, Email: c.Email, Phone: c.Phone})
	}
	if len(r.contacts) == 0 {
		for _, c := range p.Contacts {
			d.Contacts = append(d.Contacts, model.Contact{Role: c.Role, Name: c.Name, Org: c.Org, Email: c.Email, Phone: c.Phone})
		}
	}
}

// reconcileDNS folds the DNS signal into the verdict without ever overriding a
// definitive registry answer.
func reconcileDNS(d *model.Domain, resolves bool, warnings *[]model.Notice) *model.Domain {
	alerts, confidence := dnsSignals(d, resolves, warnings)
	d.Alerts = append(d.Alerts, alerts...)
	if confidence != nil {
		d.Confidence = *confidence
	}
	return d
}

// dnsSignals turns the DNS probe into caveats, plus a reduced confidence when
// the probe argues against the registry's answer.
//
// The probe always measures the registrable domain, which is what the cache
// entry describes. A subdomain's own A records would say nothing about whether
// the registrable domain is registered, so there is deliberately no
// subdomain special case here any more: the caller's name never enters this
// decision.
func dnsSignals(d *model.Domain, resolves bool, warnings *[]model.Notice) ([]model.Notice, *model.Confidence) {
	weakened := model.ConfidenceGood
	switch {
	case d.Verdict == model.VerdictAvailable && resolves:
		if d.Confidence == model.ConfidenceStrong {
			return []model.Notice{model.NoticeDNSResolvesButAvailable}, &weakened
		}
		return []model.Notice{model.NoticeDNSResolvesButAvailable}, nil
	case d.Verdict == model.VerdictRegistered && !resolves:
		return []model.Notice{model.NoticeRegisteredWithoutDNS}, nil
	case d.Verdict == model.VerdictUnknown:
		if resolves {
			weak := model.ConfidenceWeak
			return []model.Notice{model.NoticeUnknownButDNS}, &weak
		}
		if warnings != nil {
			*warnings = append(*warnings, model.WarningNoAnswerNoDNS)
		}
	}
	return nil, nil
}

// expiryAlerts adds renewal-risk hints.
func expiryAlerts(d *model.Domain) []model.Notice {
	if d.ExpiresAt == nil || d.Verdict != model.VerdictRegistered {
		return nil
	}
	days := int(time.Until(*d.ExpiresAt).Hours() / 24)
	switch {
	case days < 0:
		return []model.Notice{model.NoticeExpired}
	case days <= 7:
		return []model.Notice{model.NoticeExpiresWithin7Days}
	case days <= 30:
		return []model.Notice{model.NoticeExpiresWithin30Days}
	}
	return nil
}

// eppURL maps a status code to canonical ICANN documentation.
func eppURL(code string) string {
	slug := strings.ToLower(strings.TrimSpace(code))
	slug = strings.ReplaceAll(slug, " ", "")
	slug = strings.ReplaceAll(slug, "_", "")
	if slug == "" {
		return ""
	}
	switch slug {
	case "clientdeleteprohibited", "clienttransferprohibited", "clientupdateprohibited",
		"clientrenewprohibited", "clienthold", "serverdeleteprohibited",
		"servertransferprohibited", "serverupdateprohibited", "serverrenewprohibited",
		"serverhold", "inactive", "ok", "pendingcreate", "pendingdelete",
		"pendingrenew", "pendingrestore", "pendingtransfer", "pendingupdate",
		"redemptionperiod", "renewperiod", "transferperiod", "addperiod":
		return "https://icann.org/epp#" + slug
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// toUnicode converts a punycode name back to its display form.
func toUnicode(ascii string) string {
	out, err := idna.Lookup.ToUnicode(ascii)
	if err != nil || out == ascii {
		return ""
	}
	return out
}

// maxRawPreview bounds the upstream payload kept on a result.
const maxRawPreview = 16 << 10

// truncateRaw caps the payload so one huge response cannot bloat a cached
// entry or a JSON body.
func truncateRaw(raw string) string {
	if len(raw) <= maxRawPreview {
		return raw
	}
	return raw[:maxRawPreview]
}
