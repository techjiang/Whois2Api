package parse

import (
	"regexp"
	"strings"
)

// Outcome is what a single upstream response told us.
type Outcome int

const (
	// OutcomeUnusable means the response carries no reliable signal.
	OutcomeUnusable Outcome = iota
	// OutcomeFound means an authoritative record was returned.
	OutcomeFound
	// OutcomeNotFound means the server explicitly stated the object is absent.
	OutcomeNotFound
	// OutcomeRateLimited means the server refused to answer due to throttling.
	OutcomeRateLimited
	// OutcomeBlocked means the server refused this client outright.
	OutcomeBlocked
	// OutcomeRestricted means the name exists but the registry withholds the
	// record (.ca/.nz/.kr usage restrictions). It is a positive statement that
	// the domain is taken, so it must never be reported as available.
	OutcomeRestricted
)

func (o Outcome) String() string {
	switch o {
	case OutcomeFound:
		return "found"
	case OutcomeNotFound:
		return "not_found"
	case OutcomeRateLimited:
		return "rate_limited"
	case OutcomeBlocked:
		return "blocked"
	case OutcomeRestricted:
		return "restricted"
	default:
		return "unusable"
	}
}

// refusals are checked first and anchored to line start. Anchoring matters:
// legal disclaimers in *.io/.me/.ai records literally contain the words
// "rate limited" and "not permitted", and a substring match would flip every
// registered domain into "unknown"/"available".
var refusals = []struct {
	re  *regexp.Regexp
	out Outcome
}{
	{regexp.MustCompile(`(?i)^>>>\s*your request has been rate limited`), OutcomeRateLimited},
	{regexp.MustCompile(`(?i)^\s*error:\s*ratelimit exceeded`), OutcomeRateLimited},
	{regexp.MustCompile(`(?i)^access to the whois and rdap services is rate limited`), OutcomeRateLimited},
	{regexp.MustCompile(`(?i)^requests of this client are not permitted`), OutcomeBlocked},
	{regexp.MustCompile(`(?i)^the whois service is not available`), OutcomeBlocked},
	{regexp.MustCompile(`(?i)^\s*query refused`), OutcomeBlocked},
	// .cn throttles with this exact sentence.
	{regexp.MustCompile(`(?i)^\s*queried interval is too short`), OutcomeRateLimited},
	// .hk answers with a bare opaque token when the client is over quota.
	// Verified live: querying twice in quick succession yields "CMM174".
	{regexp.MustCompile(`(?i)^\s*CMM\d+\s*$`), OutcomeRateLimited},
	// .cn answers this for names it will not sell online (reserved/IDN policy).
	// It is emphatically not a statement that the name is free.
	{regexp.MustCompile(`(?i)^\s*the domain name you apply can ?not be registered online`), OutcomeBlocked},
	{regexp.MustCompile(`(?i)^\s*%?\s*no such host`), OutcomeNotFound},
}

// restrictedPatterns describe registries that answer "exists, but I will not
// show you". Reporting these as available would be dangerously wrong.
var restrictedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)usage restrictions applied`),
	regexp.MustCompile(`(?i)restricted to specifically qualified registrants`),
	regexp.MustCompile(`(?i)등록자격이 제한된 도메인이름`),
	regexp.MustCompile(`(?i)domain name is restricted`),
	// .om answers this for names that exist in the registry but are reserved.
	regexp.MustCompile(`(?i)^\s*reserved domain name\s*$`),
}

// notFoundPatterns are the explicit "no such object" statements collected from
// live registry responses (see internal/parse/testdata). Each one is an
// affirmative statement of absence, never merely an absence of data.
var notFoundPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*no match for\b`),
	regexp.MustCompile(`(?i)^\s*domain not found\.?\s*$`),
	regexp.MustCompile(`(?i)^\s*the queried object does not exist\b`),
	regexp.MustCompile(`(?i)^\s*no data found\s*$`),
	regexp.MustCompile(`(?i)^\s*no match!!\s*$`),
	regexp.MustCompile(`(?i)^\s*no entries found\b`),
	regexp.MustCompile(`(?i)^\s*no matching record\.?\s*$`),
	regexp.MustCompile(`(?i)^\s*the domain has not been registered\.?\s*$`),
	regexp.MustCompile(`(?i)^\s*no found\s*$`),
	regexp.MustCompile(`(?i)^\s*not found:\s*\S`),
	regexp.MustCompile(`(?i)^\s*no information available about domain name\b`),
	regexp.MustCompile(`(?i)^\s*no match found for\b`),
	regexp.MustCompile(`(?i)^\s*el dominio no se encuentra registrado\b`),
	regexp.MustCompile(`(?i)^\s*no_se_encuentro_el_objeto\b`),
	regexp.MustCompile(`(?i)^\s*/?object_not_found\b`),
	regexp.MustCompile(`(?i):\s*no entries found\.?\s*$`),
	regexp.MustCompile(`(?i)^\s*no match found\.?\s*$`),
	regexp.MustCompile(`(?i)^\s*no entries found\.?\s*$`),
	regexp.MustCompile(`(?i)^\s*no object found!?\s*$`),
	regexp.MustCompile(`(?i)^%%?\s*not found\.?\s*$`),
	regexp.MustCompile(`(?i)^\s*no entries found for domain\b`),
	// .za prints "Available" on its own line before the name.
	regexp.MustCompile(`(?i)^\s*available\s*$`),
	regexp.MustCompile(`(?i)^\s*available domain\s*:`),
	regexp.MustCompile(`(?i)^\s*no data found\s*$`),
	regexp.MustCompile(`(?i)^\s*(?:domain status|message|status)\s*:\s*no object found\b`),
	regexp.MustCompile(`(?i)^\s*no object found\b`),
	// .bz answers with a bespoke error wrapper.
	regexp.MustCompile(`(?i)^\s*whois error:\s*no match for\b`),
	regexp.MustCompile(`(?i)상기 도메인이름은 등록되어 있지 않습니다`),
	regexp.MustCompile(`(?i)^\s*domain "?[^"\s]+"? not found\.?\s*$`),
	regexp.MustCompile(`(?i)^\s*is free\s*$`),
	regexp.MustCompile(`(?i)^\s*domain\s+\S+\s+is free\s*$`),
}

// takenStatements are statements that a name is not obtainable, phrased as a
// denial of availability. .hk answers this for names that are reserved or
// otherwise held back (verified: bank.hk, nic.hk), while genuinely unused names
// get "The domain has not been registered." Reading this as "available" would
// invert the verdict, so it maps to "restricted": the name exists in some form
// but no record details are published.
var takenStatements = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*this domain is currently not available for registration`),
}

// availableStatusRe matches a status line that affirmatively means "free".
// The value must be one of the known free words; "connect" (.de) means
// registered, not free.
var availableStatusRe = regexp.MustCompile(`(?i)^\s*(?:domain\s+)?(?:registration\s+)?status\s*:\s*(free|available)\s*$`)

// availableForRegistrationRe matches the "you can buy this" phrasing used by
// .cloud/.in/.my, which is authoritative.
var availableForRegistrationRe = regexp.MustCompile(`(?i)domain\s+\S+\s+is available for registration`)

// foundMarkers indicate a real registration record. Any one is enough.
var foundMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*domain name\s*:\s*\S`),
	regexp.MustCompile(`(?i)^\s*domain\s*:\s*\S`),
	regexp.MustCompile(`(?i)^\s*\[domain name\]\s*\S`),
	regexp.MustCompile(`(?i)^\s*domain name:\s*\S`),
	regexp.MustCompile(`(?i)^\s*creation date\s*:`),
	regexp.MustCompile(`(?i)^\s*created(?: on)?\s*:`),
	regexp.MustCompile(`(?i)^\s*registrar\s*:`),
	regexp.MustCompile(`(?i)^\s*registrar:\s*\S`),
	regexp.MustCompile(`(?i)^\s*registrant\s*:`),
	regexp.MustCompile(`(?i)^\s*name server\s*:`),
	regexp.MustCompile(`(?i)^\s*nserver\s*:`),
	regexp.MustCompile(`(?i)^\s*nameserver\s*:`),
	regexp.MustCompile(`(?i)^\s*registry expiry date\s*:`),
	regexp.MustCompile(`(?i)^\s*(?:expiry|expires|expiration)(?: date)?\s*:`),
	regexp.MustCompile(`(?i)^\s*eppstatus\s*:`),
	regexp.MustCompile(`(?i)^\s*\[registrant\]`),
	regexp.MustCompile(`(?i)^\s*holder-c\s*:`),
	regexp.MustCompile(`(?i)^\s*roid\s*:`),
}

// Classify decides what a WHOIS text response means. The order of checks is
// the entire safety property of this service:
//
//  1. Refusals (rate limits, blocks) must win over everything else, because a
//     throttled server returns almost nothing and "almost nothing" must never
//     be read as "the domain is free".
//  2. Explicit "no such object" statements mean available.
//  3. A record-shaped body means registered.
//  4. Anything else is unusable, and the caller reports "unknown".
func Classify(text string) (Outcome, string) {
	lines := nonCommentLines(text)
	if len(lines) == 0 {
		// Some servers (.th) put the authoritative answer inside a comment
		// line, so an all-comment body still needs a look.
		if out, reason := classifyAllComment(text); out != OutcomeUnusable {
			return out, reason
		}
		return OutcomeUnusable, "empty response"
	}
	// 1. Refusals first. Only the head of the response is considered so that
	// long legal footers cannot masquerade as a refusal.
	head := lines
	if len(head) > 8 {
		head = head[:8]
	}
	for _, line := range head {
		for _, r := range refusals {
			if r.re.MatchString(line) {
				return r.out, strings.TrimSpace(line)
			}
		}
	}
	// 2. "Exists but withheld" outranks availability: a restricted registry
	//    answers with an error code, and a naive client would read that as
	//    "the domain is free".
	for _, line := range lines {
		for _, re := range restrictedPatterns {
			if re.MatchString(line) {
				return OutcomeRestricted, strings.TrimSpace(line)
			}
		}
	}
	// 3. Affirmative "already taken" statements, which read like a denial of
	//    availability but mean the opposite.
	for _, line := range lines {
		for _, re := range takenStatements {
			if re.MatchString(line) {
				return OutcomeRestricted, strings.TrimSpace(line)
			}
		}
	}
	// 4. Affirmative availability statements.
	for _, line := range lines {
		if availableStatusRe.MatchString(line) {
			return OutcomeNotFound, strings.TrimSpace(line)
		}
		if availableForRegistrationRe.MatchString(line) {
			return OutcomeNotFound, strings.TrimSpace(line)
		}
	}
	for _, line := range lines {
		for _, re := range notFoundPatterns {
			if re.MatchString(line) {
				return OutcomeNotFound, strings.TrimSpace(line)
			}
		}
	}
	// .eu/.be/.lt style: "Status: AVAILABLE" already handled above; the plain
	// "<name> is free" (.nl) form is covered by notFoundPatterns.
	// 5. A record-shaped body means the object exists.
	markers := 0
	for _, line := range lines {
		for _, re := range foundMarkers {
			if re.MatchString(line) {
				markers++
				break
			}
		}
	}
	// One marker is enough: registries like .de answer with just
	// "Domain: name" + "Status: connect". Availability and not-found
	// statements were already ruled out above, so a record-shaped line here
	// really does mean the object exists.
	if markers >= 1 {
		return OutcomeFound, ""
	}
	return OutcomeUnusable, "no recognizable record structure"
}

// classifyAllComment handles bodies where every line is a comment but one of
// them is the actual verdict.
func classifyAllComment(text string) (Outcome, string) {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		line = strings.TrimSpace(strings.TrimLeft(line, "%#*"))
		if line == "" {
			continue
		}
		for _, re := range notFoundPatterns {
			if re.MatchString(line) {
				return OutcomeNotFound, line
			}
		}
		for _, re := range restrictedPatterns {
			if re.MatchString(line) {
				return OutcomeRestricted, line
			}
		}
	}
	return OutcomeUnusable, ""
}

// nonCommentLines drops blank and comment-only lines. Comment prefixes seen in
// the wild: "%", "%%", "#", "*" and bracketed banner blocks.
func nonCommentLines(text string) []string {
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		switch line[0] {
		case '%', '#', '*':
			continue
		case '[':
			// Keep JPRS fields like "[Domain Name]   FOO.JP".
			if !strings.Contains(line, "]") {
				continue
			}
		}
		if strings.HasPrefix(line, ">>>") && !strings.Contains(strings.ToLower(line), "available") &&
			!strings.Contains(strings.ToLower(line), "rate limited") {
			continue
		}
		out = append(out, line)
	}
	return out
}
