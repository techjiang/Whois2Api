package parse

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// dateLayouts are tried in order. WHOIS servers are wildly inconsistent, so we
// accept RFC3339, dotted European dates, bare "YYYYMMDD" stamps and more.
// Ambiguous day/month layouts are handled separately in parseAmbiguous.
var dateLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006-01-02",
	"2006.01.02 15:04:05",
	"2006.01.02",
	"2006/01/02",
	time.RFC1123Z,
	time.RFC1123,
	"Mon Jan 2 15:04:05 2006",
	"20060102",
	"02-Jan-2006",
	"2-Jan-2006",
	"Jan 2 2006",
	"2006-01",
}

// ambiguousLayouts are day/month layouts whose order cannot be inferred from
// the layout text alone; they are tried last with explicit validation.
var ambiguousLayouts = []string{
	"02.01.2006 15:04:05",
	"02.01.2006",
	"02/01/2006",
}

var zoneAnnotationRe = regexp.MustCompile(`(?i)\s*\(?\s*(?:UTC|GMT|JST|CET|CEST|EST|EDT|PST|PDT|[+-]\d{2}:?\d{2})\s*\)?\s*$`)

// zoneWords maps a trailing zone name to a fixed offset in seconds.
var zoneWords = []struct {
	suffix string
	offset int
}{
	{"CEST", 2 * 3600},
	{"CET", 3600},
	{"JST", 9 * 3600},
	{"EDT", -4 * 3600},
	{"EST", -5 * 3600},
	{"PDT", -7 * 3600},
	{"PST", -8 * 3600},
}

// ParseDate makes a best effort at the many real-world timestamp shapes.
// It returns nil rather than a plausible-but-wrong time.
func ParseDate(raw string) *time.Time {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	// Strip parenthesised or trailing zone labels we cannot feed to time.Parse.
	if loc, trimRest := zoneFromSuffix(s); loc != nil {
		if t, ok := tryLayouts(trimRest, loc); ok {
			return &t
		}
	}
	cleaned := strings.TrimSpace(zoneAnnotationRe.ReplaceAllString(s, ""))
	if cleaned == "" {
		cleaned = s
	}
	if t, ok := tryLayouts(cleaned, time.UTC); ok {
		return &t
	}
	// Dotted/slashed dates: these registries write day-first ("30.10.1997").
	// We never "fix up" a successful parse -- a value like 13.05.1997 is a
	// legitimate 13 May and swapping fields would corrupt it.
	for _, layout := range ambiguousLayouts {
		if t, err := time.ParseInLocation(layout, cleaned, time.UTC); err == nil {
			return &t
		}
	}
	return nil
}

func tryLayouts(s string, loc *time.Location) (time.Time, bool) {
	for _, layout := range dateLayouts {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// zoneFromSuffix detects a trailing zone label and returns the stripped value.
func zoneFromSuffix(s string) (*time.Location, string) {
	up := strings.ToUpper(s)
	for _, zw := range zoneWords {
		if strings.HasSuffix(up, zw.suffix) {
			rest := strings.TrimSpace(strings.TrimRight(s[:len(s)-len(zw.suffix)], "(, "))
			if rest == "" {
				return nil, s
			}
			return time.FixedZone(zw.suffix, zw.offset), rest
		}
	}
	if strings.HasSuffix(up, "UTC") || strings.HasSuffix(up, "GMT") {
		rest := strings.TrimSpace(strings.TrimRight(s[:len(s)-3], "(, "))
		if rest == "" {
			return nil, s
		}
		return time.UTC, rest
	}
	return nil, s
}

// DaysUntil converts an expiry timestamp into whole days from now.
func DaysUntil(t *time.Time) *int {
	if t == nil {
		return nil
	}
	days := int(time.Until(*t).Hours() / 24)
	return &days
}

// parseBoolish interprets the many spellings of yes/no used by registries.
func parseBoolish(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "y", "true", "1", "signed", "active", "connect":
		return true, true
	case "no", "n", "false", "0", "unsigned", "inactive", "free":
		return false, true
	}
	return false, false
}

// atoiSafe parses an integer, tolerating surrounding punctuation.
func atoiSafe(s string) (int, bool) {
	s = strings.TrimSpace(strings.Trim(s, ".,;()[]"))
	if s == "" {
		return 0, false
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}
