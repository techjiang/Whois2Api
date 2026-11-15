package parse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RDAP document shapes. Only the fields we actually use are modeled; RDAP
// allows far more, and unknown members are simply ignored by encoding/json.

type rdapDocument struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	LDHName         string       `json:"ldhName"`
	UnicodeName     string       `json:"unicodeName"`
	Status          []string     `json:"status"`
	Events          []rdapEvent  `json:"events"`
	Nameservers     []rdapNS     `json:"nameservers"`
	Entities        []rdapEntity `json:"entities"`
	SecureDNS       *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	ErrorCode   int      `json:"errorCode"`
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapEntity struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
	PublicIDs  []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

// RDAPResult is the normalized outcome of an RDAP query.
type RDAPResult struct {
	// Verdict is OutcomeFound, OutcomeNotFound or OutcomeUnusable.
	Verdict Outcome
	// Reason explains a not-found answer.
	Reason string
	Parsed Parsed
	// Contacts are the richer parties RDAP exposes.
	Contacts   []Contact
	SecureDNS  string
	RegistryID string
}

// ParseRDAP interprets an RDAP JSON body. httpStatus is the HTTP status code so
// that error documents (which legally carry 404 with a description) are handled.
func ParseRDAP(body []byte, httpStatus int) RDAPResult {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		// Some registries answer 404 with a bare, empty body. The status code
		// is the whole message, and it is a positive statement of absence.
		if httpStatus == http.StatusNotFound {
			return RDAPResult{Verdict: OutcomeNotFound, Reason: "RDAP HTTP 404 with empty body"}
		}
		return RDAPResult{Verdict: OutcomeUnusable, Reason: "empty RDAP body"}
	}
	var doc rdapDocument
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return RDAPResult{Verdict: OutcomeUnusable, Reason: "malformed RDAP JSON"}
	}

	// A document that declares a domain object is authoritative.
	if strings.EqualFold(doc.ObjectClassName, "domain") && doc.LDHName != "" {
		return buildRDAPResult(doc)
	}

	// Error documents: 404 means "no such object" only when the registry did
	// not say the name is merely restricted.
	if httpStatus == 404 || doc.ErrorCode == 404 {
		reason := rdapErrorText(doc)
		if isRestrictedReason(reason) {
			return RDAPResult{Verdict: OutcomeRestricted, Reason: reason}
		}
		return RDAPResult{Verdict: OutcomeNotFound, Reason: reason}
	}
	// Some registries answer 400/422 for malformed or absent names.
	if httpStatus >= 400 && httpStatus < 500 && httpStatus != 429 {
		return RDAPResult{Verdict: OutcomeNotFound, Reason: rdapErrorText(doc)}
	}
	return RDAPResult{Verdict: OutcomeUnusable, Reason: fmt.Sprintf("unexpected RDAP response (HTTP %d)", httpStatus)}
}

func rdapErrorText(doc rdapDocument) string {
	parts := append([]string{}, doc.Description...)
	if doc.Title != "" {
		parts = append(parts, doc.Title)
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// isRestrictedReason detects the "exists but withheld" wording so it is never
// downgraded to "available".
func isRestrictedReason(reason string) bool {
	low := strings.ToLower(reason)
	for _, marker := range []string{"usage restrictions", "restricted", "not permitted", "withheld", "redacted"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

func buildRDAPResult(doc rdapDocument) RDAPResult {
	res := RDAPResult{Verdict: OutcomeFound, RegistryID: doc.Handle}
	for _, ev := range doc.Events {
		switch strings.ToLower(ev.Action) {
		case "registration":
			if res.Parsed.Created == "" {
				res.Parsed.Created = ev.Date
			}
		case "last changed", "last update of rdap database":
			if strings.EqualFold(ev.Action, "last changed") && res.Parsed.Updated == "" {
				res.Parsed.Updated = ev.Date
			}
		case "expiration":
			if res.Parsed.Expires == "" {
				res.Parsed.Expires = ev.Date
			}
		}
	}
	for _, st := range doc.Status {
		if code := normalizeStatus(st); code != "" {
			res.Parsed.Statuses = append(res.Parsed.Statuses, code)
		}
	}
	for _, ns := range doc.Nameservers {
		if host := normalizeNameServer(ns.LDHName); host != "" {
			res.Parsed.NameServers = append(res.Parsed.NameServers, host)
		}
	}
	if doc.SecureDNS != nil {
		if doc.SecureDNS.DelegationSigned {
			res.SecureDNS = "signed"
		} else {
			res.SecureDNS = "unsigned"
		}
	}
	for _, ent := range doc.Entities {
		collectRDAPEntity(ent, &res)
	}
	res.Parsed.Statuses = dedupeSorted(res.Parsed.Statuses)
	res.Parsed.NameServers = dedupeSorted(res.Parsed.NameServers)
	return res
}

// collectRDAPEntity walks the registrar/registrant tree, including nested
// entities (registrars nest their abuse contacts).
func collectRDAPEntity(ent rdapEntity, res *RDAPResult) {
	roles := make([]string, len(ent.Roles))
	for i, r := range ent.Roles {
		roles[i] = strings.ToLower(r)
	}
	hasRole := func(name string) bool {
		for _, r := range roles {
			if r == name {
				return true
			}
		}
		return false
	}

	name, org, email, phone := parseVCard(ent.VCardArray)

	if hasRole("registrar") && res.Parsed.Registrar == "" {
		res.Parsed.Registrar = firstNonEmpty(name, org)
		if res.Parsed.RegistrarID == "" {
			for _, pid := range ent.PublicIDs {
				if strings.Contains(strings.ToLower(pid.Type), "iana") {
					res.Parsed.RegistrarID = pid.Identifier
					break
				}
			}
			if res.Parsed.RegistrarID == "" {
				res.Parsed.RegistrarID = ent.Handle
			}
		}
	}
	if (hasRole("registrant") || hasRole("administrative") || hasRole("technical") ||
		hasRole("abuse")) && (name != "" || org != "" || email != "") {
		role := "registrant"
		switch {
		case hasRole("registrant"):
			role = "registrant"
		case hasRole("abuse"):
			role = "abuse"
		case hasRole("administrative"):
			role = "administrative"
		case hasRole("technical"):
			role = "technical"
		}
		res.Contacts = append(res.Contacts, Contact{
			Role: role, Name: name, Org: org, Email: email, Phone: phone,
		})
	}
	for _, child := range ent.Entities {
		collectRDAPEntity(child, res)
	}
}

// parseVCard pulls the common name, organization, email and phone out of the
// jCard structure RDAP uses (["vcard", [[name, params, type, value], ...]]).
func parseVCard(raw json.RawMessage) (name, org, email, phone string) {
	if len(raw) == 0 {
		return
	}
	var outer []json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil || len(outer) < 2 {
		return
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(outer[1], &props); err != nil {
		return
	}
	for _, prop := range props {
		if len(prop) < 4 {
			continue
		}
		var key string
		if err := json.Unmarshal(prop[0], &key); err != nil {
			continue
		}
		var value string
		if err := json.Unmarshal(prop[3], &value); err != nil {
			// Values may be arrays (e.g. multiple emails).
			var list []string
			if err2 := json.Unmarshal(prop[3], &list); err2 == nil && len(list) > 0 {
				value = list[0]
			} else {
				continue
			}
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "fn":
			if name == "" {
				name = value
			}
		case "org":
			if org == "" {
				org = value
			}
		case "email":
			if email == "" {
				email = obscureEmail(strings.TrimPrefix(value, "mailto:"))
			}
		case "tel":
			if phone == "" {
				phone = strings.TrimSpace(strings.TrimPrefix(value, "tel:"))
			}
		}
	}
	return
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
