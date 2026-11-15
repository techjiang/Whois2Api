package parse

import (
	"regexp"
	"sort"
	"strings"
)

// Parsed holds the structured fields extracted from a WHOIS text response.
// Every field is optional: many registries redact or omit values entirely.
type Parsed struct {
	Registrar    string
	RegistrarID  string
	RegistrarURL string
	RegistryID   string
	Created      string
	Updated      string
	Expires      string
	Statuses     []string
	NameServers  []string
	DNSSEC       string
	Contacts     []Contact
}

// Contact is a party mentioned in the record.
type Contact struct {
	Role  string
	Name  string
	Org   string
	Email string
	Phone string
}

// fieldPatterns maps a canonical field to the label spellings seen in the wild.
// Order matters: the first matching pattern wins for single-value fields.
var fieldPatterns = []struct {
	field string
	re    *regexp.Regexp
}{
	{"registrar_url", regexp.MustCompile(`(?i)^(?:registrar\s+url|registrar\s+website|registrar\s?url)\s*:\s*(\S.*)$`)},
	{"registrar_id", regexp.MustCompile(`(?i)^(?:registrar\s+iana\s+id|registrar\s+id|iana\s+id)\s*:\s*(\S.*)$`)},
	{"registrar", regexp.MustCompile(`(?i)^(?:sponsoring\s+)?registrar\s*:\s*(\S.*)$`)},
	{"registry_id", regexp.MustCompile(`(?i)^(?:registry\s+domain\s+id|roid)\s*:\s*(\S.*)$`)},
	{"created", regexp.MustCompile(`(?i)^(?:creation\s+date|created(?:\s+on)?|registration\s+time|registered(?:\s+on)?|registration\s+date|domain\s+registration\s+date|assigned)\s*:\s*(\S.*)$`)},
	{"updated", regexp.MustCompile(`(?i)^(?:updated\s+date|last[-\s]?update(?:d)?|last\s+modified|modified|changed)\s*:\s*(\S.*)$`)},
	{"expires", regexp.MustCompile(`(?i)^(?:registry\s+expiry\s+date|registrar\s+registration\s+expiration\s+date|expiry\s+date|expiration\s+(?:date|time)|expires?(?:\s+on)?|renewal\s+date|validity|paid-till|free-date)\s*:\s*(\S.*)$`)},
	{"status", regexp.MustCompile(`(?i)^(?:domain\s+)?(?:epp)?status\s*:\s*(\S.*)$`)},
	{"eppstatus", regexp.MustCompile(`(?i)^eppstatus\s*:\s*(\S.*)$`)},
	{"nserver", regexp.MustCompile(`(?i)^(?:name\s+servers?|nserver|nameserver|ns)\s*:\s*(\S.*)$`)},
	{"nserver_bracket", regexp.MustCompile(`(?i)^\[name\s+server\]\s*:\s*(\S.*)$`)},
	{"dnssec", regexp.MustCompile(`(?i)^(?:dnssec|signed)\s*:\s*(\S.*)$`)},
	{"registrant_name", regexp.MustCompile(`(?i)^(?:registrant\s+name|registrant|holder|\[registrant\])\s*:\s*(\S.*)$`)},
	{"registrant_org", regexp.MustCompile(`(?i)^(?:registrant\s+organization|registrant\s+organisation|org)\s*:\s*(\S.*)$`)},
	{"registrant_email", regexp.MustCompile(`(?i)^(?:registrant\s+email|e-?mail)\s*:\s*(\S.*)$`)},
	{"registrant_phone", regexp.MustCompile(`(?i)^(?:registrant\s+phone|phone)\s*:\s*(\S.*)$`)},
}

// valueStopWords cut a value where a second field begins on the same line.
var multiValueSplitRe = regexp.MustCompile(`\s{2,}|\s+\|\s+`)

// ParseWhoIs extracts structured fields and normalizes them.
func ParseWhoIs(text string) Parsed {
	var p Parsed
	lines := strings.Split(text, "\n")
	seenNS := map[string]bool{}
	seenStatus := map[string]bool{}

	for _, raw := range lines {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		// A comment line can never carry a field, but JPRS uses "[X]" labels
		// which are not comments; nonCommentLines logic is not reused here
		// because we need the label text.
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		for _, fp := range fieldPatterns {
			m := fp.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			value := cleanValue(m[1])
			if value == "" {
				continue
			}
			switch fp.field {
			case "registrar":
				if p.Registrar == "" {
					p.Registrar = stripTrailingID(value)
				}
			case "registrar_id":
				if p.RegistrarID == "" {
					p.RegistrarID = value
				}
			case "registrar_url":
				if p.RegistrarURL == "" {
					p.RegistrarURL = value
				}
			case "registry_id":
				if p.RegistryID == "" {
					p.RegistryID = stripRedacted(value)
				}
			case "created":
				if p.Created == "" {
					p.Created = value
				}
			case "updated":
				if p.Updated == "" {
					p.Updated = value
				}
			case "expires":
				if p.Expires == "" {
					p.Expires = value
				}
			case "status", "eppstatus":
				for _, chunk := range multiValueSplitRe.Split(value, -1) {
					code := normalizeStatus(chunk)
					if code == "" || seenStatus[code] {
						continue
					}
					seenStatus[code] = true
					p.Statuses = append(p.Statuses, code)
				}
			case "nserver", "nserver_bracket":
				for _, chunk := range multiValueSplitRe.Split(value, -1) {
					ns := normalizeNameServer(chunk)
					if ns == "" || seenNS[ns] {
						continue
					}
					seenNS[ns] = true
					p.NameServers = append(p.NameServers, ns)
				}
			case "dnssec":
				if p.DNSSEC == "" {
					p.DNSSEC = normalizeDNSSEC(value)
				}
			case "registrant_name":
				if len(p.Contacts) == 0 {
					p.Contacts = append(p.Contacts, Contact{Role: "registrant"})
				}
				if p.Contacts[0].Name == "" {
					p.Contacts[0].Name = stripRedacted(value)
				}
			case "registrant_org":
				if len(p.Contacts) == 0 {
					p.Contacts = append(p.Contacts, Contact{Role: "registrant"})
				}
				if p.Contacts[0].Org == "" {
					p.Contacts[0].Org = stripRedacted(value)
				}
			case "registrant_email":
				if len(p.Contacts) == 0 {
					p.Contacts = append(p.Contacts, Contact{Role: "registrant"})
				}
				if p.Contacts[0].Email == "" {
					p.Contacts[0].Email = obscureEmail(stripRedacted(value))
				}
			case "registrant_phone":
				if len(p.Contacts) == 0 {
					p.Contacts = append(p.Contacts, Contact{Role: "registrant"})
				}
				if p.Contacts[0].Phone == "" {
					p.Contacts[0].Phone = stripRedacted(value)
				}
			}
			break
		}
	}
	p.Statuses = dedupeSorted(p.Statuses)
	return p
}

// cleanValue trims whitespace and drops trailing zone/annotation noise.
func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\t")
	return v
}

// stripTrailingID removes the "(9999)" IANA id some registries append to the
// registrar name.
var trailingParenIDRe = regexp.MustCompile(`\s*\((\d+)\)\s*$`)

func stripTrailingID(v string) string {
	return strings.TrimSpace(trailingParenIDRe.ReplaceAllString(v, ""))
}

// redactedMarkers are values registries emit instead of real data.
var redactedMarkers = map[string]bool{
	"redacted":                 true,
	"redacted for privacy":     true,
	"not disclosed":            true,
	"statutory masking":        true,
	"non-public data":          true,
	"gdpr masked":              true,
	"data protected":           true,
	"withheld for privacy":     true,
	"private":                  true,
	"none":                     true,
	"n/a":                      true,
	"na":                       true,
	"-":                        true,
	"hidden upon user request": true,
}

// stripRedacted returns "" for placeholder values so callers can omit the field
// instead of exposing junk like "REDACTED FOR PRIVACY".
func stripRedacted(v string) string {
	trimmed := strings.TrimSpace(strings.TrimSuffix(v, "."))
	if trimmed == "" {
		return ""
	}
	if redactedMarkers[strings.ToLower(trimmed)] {
		return ""
	}
	if strings.Contains(strings.ToLower(trimmed), "redacted") {
		return ""
	}
	return trimmed
}

// obscureEmail neutralizes address-obfuscation forms registries use to defeat
// scrapers ("name at example dot com", "name [at] example [dot] com").
var (
	atObfuscationRe  = regexp.MustCompile(`(?i)\s*[\[\(\{]\s*at\s*[\]\)\}]\s*|\s+at\s+`)
	dotObfuscationRe = regexp.MustCompile(`(?i)\s*[\[\(\{]\s*dot\s*[\]\)\}]\s*|\s+dot\s+`)
	emailShapeRe     = regexp.MustCompile(`^[\w.!#$%&'*+/=?^` + "`" + `{|}~-]+@[\w-]+(\.[\w-]+)+$`)
)

func obscureEmail(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if emailShapeRe.MatchString(v) {
		return v
	}
	deobfuscated := atObfuscationRe.ReplaceAllString(v, "@")
	deobfuscated = dotObfuscationRe.ReplaceAllString(deobfuscated, ".")
	if emailShapeRe.MatchString(deobfuscated) {
		return deobfuscated
	}
	// Not an address we understand; do not echo garbage into the API.
	if strings.Contains(v, "@") && !strings.ContainsAny(v, " <>") {
		return v
	}
	return ""
}

// statusURLFragment attaches the canonical EPP documentation link.
var eppURLRe = regexp.MustCompile(`https?://\S+`)

// normalizeStatus lowercases a status code and strips its documentation URL,
// which the API re-attaches from a canonical table.
func normalizeStatus(v string) string {
	v = strings.TrimSpace(v)
	if m := eppURLRe.FindString(v); m != "" {
		v = strings.TrimSpace(strings.TrimSuffix(v, m))
	}
	v = strings.Trim(v, " \t,;")
	if v == "" {
		return ""
	}
	if _, ok := parseBoolish(v); ok && !strings.ContainsAny(v, " ") {
		// Bare "yes"/"no" is a DNSSEC answer, not a status code.
		return ""
	}
	return v
}

// normalizeNameServer keeps the hostname and drops trailing glue addresses.
func normalizeNameServer(v string) string {
	v = strings.TrimSpace(v)
	// Remove bracketed glue like "ns1.example.com. [1.2.3.4]".
	if i := strings.Index(v, "["); i > 0 {
		v = v[:i]
	}
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
	if host == "" || strings.Contains(host, " ") {
		return ""
	}
	// A bare IP is not a name server name.
	if regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(host) {
		return ""
	}
	return host
}

func normalizeDNSSEC(v string) string {
	low := strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.HasPrefix(low, "unsigned"), low == "no", low == "false", low == "0":
		return "unsigned"
	case strings.HasPrefix(low, "signed"), strings.HasPrefix(low, "yes"), low == "true", low == "1":
		return "signed"
	case low == "":
		return ""
	default:
		// Values like "257 3 8 AwEAA..." are DS/DNSKEY material: signed.
		if strings.Contains(low, " ") {
			return "signed"
		}
		return low
	}
}

// dedupeSorted removes duplicates and sorts for deterministic output.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
