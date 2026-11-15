package tld

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ianaTLDList is the authoritative list of delegated top-level domains.
const ianaTLDList = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

// ianaRDAPBootstrap maps TLDs to their RDAP base URLs.
const ianaRDAPBootstrap = "https://data.iana.org/rdap/dns.json"

// wikiTLDWhois is a community-maintained TLD -> WHOIS host mapping. It is used
// only to fill gaps for ccTLDs that IANA does not publish a WHOIS host for.
const wikiTLDWhois = "https://raw.githubusercontent.com/whois-server-list/whois-server-list/master/whois-server-list.json"

// FetchIANA downloads the current TLD list plus RDAP bootstrap and merges them
// into a fresh route table. It never invents a WHOIS host: entries without a
// known server simply carry no WHOIS route and rely on RDAP.
func FetchIANA(ctx context.Context) (*Table, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	tlds, err := fetchTLDLabels(ctx, client)
	if err != nil {
		return nil, err
	}
	rdapMap, err := fetchRDAPBootstrap(ctx, client)
	if err != nil {
		return nil, err
	}
	// The WHOIS list is best-effort: a failure only costs ccTLD coverage.
	whoisMap, whoisErr := fetchWhoisList(ctx, client)

	routes := make(map[string]Route, len(tlds))
	for _, label := range tlds {
		// IDN TLDs are published as punycode already (xn--...).
		key := strings.ToLower(label)
		route := Route{}
		if urls, ok := rdapMap[key]; ok {
			route.RDAP = urls
		}
		if whoisErr == nil {
			if host, ok := whoisMap[key]; ok {
				route.WhoIs = host
			}
		}
		if route.WhoIs == "" && len(route.RDAP) == 0 {
			continue // nothing to query; leave it out rather than half-work
		}
		routes[key] = route
	}
	if len(routes) < 100 {
		return nil, fmt.Errorf("tld: refreshed table looks wrong (%d entries)", len(routes))
	}
	return NewTable(routes, "iana"), nil
}

func fetchTLDLabels(ctx context.Context, client *http.Client) ([]string, error) {
	body, err := httpGet(ctx, client, ianaTLDList)
	if err != nil {
		return nil, fmt.Errorf("tld: fetch TLD list: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, errors.New("tld: TLD list was empty")
	}
	return out, nil
}

func fetchRDAPBootstrap(ctx context.Context, client *http.Client) (map[string][]string, error) {
	body, err := httpGet(ctx, client, ianaRDAPBootstrap)
	if err != nil {
		return nil, fmt.Errorf("tld: fetch RDAP bootstrap: %w", err)
	}
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("tld: parse RDAP bootstrap: %w", err)
	}
	out := make(map[string][]string, 2048)
	for _, service := range doc.Services {
		if len(service) != 2 {
			continue
		}
		urls := make([]string, 0, len(service[1]))
		for _, u := range service[1] {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			if !strings.HasSuffix(u, "/") {
				u += "/"
			}
			urls = append(urls, u)
		}
		for _, label := range service[0] {
			key := strings.ToLower(strings.TrimSpace(label))
			if key == "" || len(urls) == 0 {
				continue
			}
			out[key] = urls
		}
	}
	if len(out) == 0 {
		return nil, errors.New("tld: RDAP bootstrap contained no services")
	}
	return out, nil
}

// fetchWhoisList reads a community TLD->WHOIS mapping.
func fetchWhoisList(ctx context.Context, client *http.Client) (map[string]string, error) {
	body, err := httpGet(ctx, client, wikiTLDWhois)
	if err != nil {
		return nil, err
	}
	// The format varies between a flat map and a list of objects; accept both.
	var flat map[string]string
	if err := json.Unmarshal(body, &flat); err == nil && len(flat) > 0 {
		out := make(map[string]string, len(flat))
		for k, v := range flat {
			key := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(k), "."))
			host := strings.ToLower(strings.TrimSpace(v))
			if key != "" && host != "" {
				out[key] = host
			}
		}
		return out, nil
	}
	var list []struct {
		TLD   string `json:"tld"`
		Whois string `json:"whois"`
		Host  string `json:"host"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, errors.New("tld: unrecognized WHOIS list format")
	}
	out := make(map[string]string, len(list))
	for _, item := range list {
		key := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(item.TLD), "."))
		host := strings.ToLower(strings.TrimSpace(item.Whois))
		if host == "" {
			host = strings.ToLower(strings.TrimSpace(item.Host))
		}
		if key != "" && host != "" {
			out[key] = host
		}
	}
	if len(out) == 0 {
		return nil, errors.New("tld: WHOIS list was empty")
	}
	return out, nil
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "whois2api/1.0 (+https://github.com/techjiang/Whois2Api)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// SaveTable persists a refreshed table next to the cache so restarts are fast.
// Failure is non-fatal: the caller keeps using the in-memory table.
func SaveTable(dataDir string, table *Table) error {
	if dataDir == "" {
		return errors.New("tld: empty data directory")
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	routes := make(map[string]struct {
		W string   `json:"w"`
		R []string `json:"r"`
	}, table.Len())
	for _, label := range table.Labels() {
		r, ok := table.Lookup(label)
		if !ok {
			continue
		}
		routes[label] = struct {
			W string   `json:"w"`
			R []string `json:"r"`
		}{W: r.WhoIs, R: r.RDAP}
	}
	blob, err := json.MarshalIndent(routes, "", " ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dataDir, "tld-table.json.tmp")
	final := filepath.Join(dataDir, "tld-table.json")
	if err := os.WriteFile(tmp, blob, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}
