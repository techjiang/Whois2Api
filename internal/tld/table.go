package tld

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed table.json
var tableJSON []byte

// Route describes how to reach the authoritative servers for one TLD.
// Data is generated from the IANA root database (see gen.go) and kept as a
// fallback for offline installs; it can be refreshed at runtime from IANA.
type Route struct {
	// WhoIs is the port-43 server, lowercase host name, empty when none exists.
	WhoIs string
	// RDAP is the ordered list of RDAP base URLs (always ending in "/").
	RDAP []string
}

// Table maps lowercased ASCII TLD labels to their routes.
type Table struct {
	routes map[string]Route
	source string
}

// EmbeddedTable returns the route table compiled into the binary.
func EmbeddedTable() (*Table, error) {
	var raw map[string]struct {
		W string   `json:"w"`
		R []string `json:"r"`
	}
	if err := json.Unmarshal(tableJSON, &raw); err != nil {
		return nil, fmt.Errorf("tld: embedded table is corrupt: %w", err)
	}
	t := &Table{routes: make(map[string]Route, len(raw)), source: "embedded"}
	for k, v := range raw {
		t.routes[strings.ToLower(k)] = Route{WhoIs: strings.ToLower(v.W), RDAP: v.R}
	}
	return t, nil
}

// NewTable builds a table from an explicit map (used by tests and refreshes).
func NewTable(routes map[string]Route, source string) *Table {
	copied := make(map[string]Route, len(routes))
	normalized := make(map[string]Route, len(routes))
	for k, v := range routes {
		key := strings.ToLower(strings.TrimSuffix(k, "."))
		rdap := make([]string, 0, len(v.RDAP))
		for _, u := range v.RDAP {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			if !strings.HasSuffix(u, "/") {
				u += "/"
			}
			rdap = append(rdap, u)
		}
		normalized[key] = Route{WhoIs: strings.ToLower(v.WhoIs), RDAP: rdap}
		copied[k] = v
	}
	return &Table{routes: normalized, source: source}
}

// Lookup resolves the route for an ASCII TLD label.
func (t *Table) Lookup(label string) (Route, bool) {
	r, ok := t.routes[strings.ToLower(strings.TrimSuffix(label, "."))]
	return r, ok
}

// Len reports how many TLDs are known.
func (t *Table) Len() int { return len(t.routes) }

// Source names where the table came from ("embedded", "iana", ...).
func (t *Table) Source() string { return t.source }

// Labels returns every known TLD label, sorted.
func (t *Table) Labels() []string {
	out := make([]string, 0, len(t.routes))
	for k := range t.routes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Stats summarizes coverage for the status endpoint.
type Stats struct {
	Total  int    `json:"total"`
	WhoIs  int    `json:"whois"`
	RDAP   int    `json:"rdap"`
	Both   int    `json:"both"`
	Source string `json:"source"`
}

// Stats computes route coverage numbers.
func (t *Table) Stats() Stats {
	s := Stats{Total: len(t.routes), Source: t.source}
	for _, r := range t.routes {
		if r.WhoIs != "" {
			s.WhoIs++
		}
		if len(r.RDAP) > 0 {
			s.RDAP++
		}
		if r.WhoIs != "" && len(r.RDAP) > 0 {
			s.Both++
		}
	}
	return s
}
