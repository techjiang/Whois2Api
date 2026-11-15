package tld

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

// ErrNotDomain reports input that cannot be interpreted as a DNS name.
var ErrNotDomain = errors.New("tld: not a valid domain name")

const (
	ruleExact     uint8 = 1 << 0 // "com", "co.uk"
	ruleWildcard  uint8 = 1 << 1 // "*.ck" stored under key "ck"
	ruleException uint8 = 1 << 2 // "!www.ck" stored under key "www.ck"
)

// List is an immutable Public Suffix List matcher.
type List struct {
	rules map[string]uint8
	// privateRules holds the rules that came from the PRIVATE section. They are
	// merged into rules for matching, but kept separately because they mean
	// something different to a lookup: a name under "github.io" or "uk.com" is
	// delegated by a third party, and the TLD registry cannot answer for it.
	privateRules map[string]uint8
	private      bool
}

// Options controls which portions of the PSL are loaded.
type Options struct {
	// Private includes the PRIVATE section (vendor suffixes such as "uk.com").
	Private bool
}

var (
	defaultList *List
	defaultOnce sync.Once
	defaultErr  error
)

// Default returns the process-wide matcher with ICANN + PRIVATE rules, which is
// what the publicsuffix.org reference suite expects.
func Default() (*List, error) {
	defaultOnce.Do(func() {
		defaultList, defaultErr = New(Options{Private: true})
	})
	return defaultList, defaultErr
}

// MustDefault panics when the embedded rules are unreadable.
func MustDefault() *List {
	l, err := Default()
	if err != nil {
		panic(err)
	}
	return l
}

// New loads the embedded PSL data according to opts.
func New(opts Options) (*List, error) {
	icann, err := gunzipBase64(pslICANNGzipB64)
	if err != nil {
		return nil, fmt.Errorf("tld: embedded ICANN rules are corrupt: %w", err)
	}
	var private string
	if opts.Private {
		private, err = gunzipBase64(pslPrivateGzipB64)
		if err != nil {
			return nil, fmt.Errorf("tld: embedded PRIVATE rules are corrupt: %w", err)
		}
	}
	l, err := parseList(icann + "\n" + private)
	if err != nil {
		return nil, err
	}
	if opts.Private {
		privateList, privErr := parseList(private)
		if privErr != nil {
			return nil, privErr
		}
		l.privateRules = privateList.rules
	}
	l.private = opts.Private
	return l, nil
}

// IsPrivateSuffix reports whether suffix is a PRIVATE-section rule: a "public
// suffix" owned by a vendor rather than a registry (github.io, uk.com,
// s3.amazonaws.com). Names below one of these are handed out by that vendor, so
// the TLD registry has no record of them and answers "no match" for a name that
// is not for sale. Treating that answer as availability is exactly the bug this
// project exists to prevent.
func (l *List) IsPrivateSuffix(suffix string) bool {
	if l == nil || len(l.privateRules) == 0 || suffix == "" {
		return false
	}
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(suffix, ".")), ".")
	for i := range labels {
		candidate := strings.Join(labels[i:], ".")
		bits, ok := l.privateRules[candidate]
		if !ok {
			continue
		}
		if bits&ruleExact != 0 && i == 0 {
			return true
		}
		// A wildcard rule whose key is the parent of this suffix ("*.ck" stored
		// under "ck") also makes it a private suffix.
		if bits&ruleWildcard != 0 {
			return true
		}
	}
	return false
}

// ParseList builds a matcher from raw list text (publicsuffix.org format).
func ParseList(text string) (*List, error) { return parseList(text) }

func parseList(text string) (*List, error) {
	rules := make(map[string]uint8, 16384)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// Rules are ASCII or U-label; drop any trailing inline comment.
		if i := strings.IndexByte(line, ' '); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSuffix(strings.ToLower(line), ".")

		var kind uint8
		switch {
		case strings.HasPrefix(line, "!"):
			kind = ruleException
			line = strings.TrimPrefix(line, "!")
		case strings.HasPrefix(line, "*."):
			kind = ruleWildcard
			line = strings.TrimPrefix(line, "*.")
		default:
			kind = ruleExact
		}
		key, err := ruleKey(line)
		if err != nil || key == "" {
			continue
		}
		rules[key] |= kind
	}
	if len(rules) == 0 {
		return nil, errors.New("tld: empty rule set")
	}
	return &List{rules: rules}, nil
}

// ruleKey converts a rule label sequence to lowercase ASCII (punycode).
func ruleKey(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if isASCII(s) {
		return s, nil
	}
	converted, err := idna.Punycode.ToASCII(s)
	if err != nil {
		// Some PSL entries use characters rejected by IDNA2008; fall back to
		// the lookup profile so the rule is still usable.
		converted, err = idna.Lookup.ToASCII(s)
		if err != nil {
			return "", err
		}
	}
	return strings.ToLower(converted), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// IncludesPrivate reports whether the PRIVATE section is loaded.
func (l *List) IncludesPrivate() bool { return l.private }

// RuleCount exposes the number of distinct rules loaded.
func (l *List) RuleCount() int { return len(l.rules) }

// Normalize lowercases and converts a domain to its ASCII (punycode) form.
// It rejects empty, over-long, or structurally invalid names.
func Normalize(name string) (ascii string, err error) {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".") // tolerate a single trailing root dot
	if name == "" || len(name) > 253 {
		return "", ErrNotDomain
	}
	// A leading dot, or any consecutive dots, means an empty label: invalid.
	if strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
		return "", ErrNotDomain
	}
	// Underscores are deliberately rejected. They are legal in DNS records
	// (_dmarc.example.com) but never in a registrable name, and letting one
	// through meant "a_b.com" was queried as typed, the registry answered
	// "no match" because no such name can exist, and the result was a confident
	// `available`.
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.':
		case r >= 0x80:
		default:
			return "", ErrNotDomain
		}
	}
	lower := strings.ToLower(name)
	var asciiName string
	if isASCII(lower) {
		asciiName = lower
	} else {
		// Lookup profile: IDNA2008 + UTS46 mapping for user-supplied input.
		converted, convErr := idna.Lookup.ToASCII(lower)
		if convErr != nil {
			return "", ErrNotDomain
		}
		asciiName = strings.ToLower(converted)
	}
	if err := validateLabels(asciiName); err != nil {
		return "", err
	}
	return asciiName, nil
}

func validateLabels(ascii string) error {
	if len(ascii) > 253 || ascii == "" {
		return ErrNotDomain
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return ErrNotDomain
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return ErrNotDomain
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
			case c == '-':
			default:
				return ErrNotDomain
			}
		}
	}
	return nil
}

// PublicSuffix returns the public suffix of an already normalized ASCII domain.
func (l *List) PublicSuffix(ascii string) string {
	suffix, _ := l.split(ascii)
	return suffix
}

// RegistrableDomain returns the eTLD+1 for a normalized ASCII domain, or "" when
// the name is itself a public suffix (e.g. "co.uk").
func (l *List) RegistrableDomain(ascii string) string {
	suffix, labels := l.split(ascii)
	if suffix == "" || len(labels) == 0 {
		return ""
	}
	suffixLabels := strings.Count(suffix, ".") + 1
	if len(labels) <= suffixLabels {
		return ""
	}
	start := len(labels) - suffixLabels - 1
	return strings.Join(labels[start:], ".")
}

// split applies the PSL prevailing-rule algorithm and reports label boundaries.
func (l *List) split(ascii string) (suffix string, labels []string) {
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if ascii == "" {
		return "", nil
	}
	labels = strings.Split(ascii, ".")
	best := 1 // implied "*" rule matches a single label
	var exceptionAt = -1
	for i := range labels {
		candidate := strings.Join(labels[i:], ".")
		bits, ok := l.rules[candidate]
		if !ok {
			continue
		}
		n := len(labels) - i
		if bits&ruleException != 0 {
			if exceptionAt < 0 || i < exceptionAt {
				exceptionAt = i
			}
			continue
		}
		if bits&ruleWildcard != 0 && n+1 > best {
			best = n + 1
		}
		if bits&ruleExact != 0 && n > best {
			best = n
		}
	}
	if exceptionAt >= 0 {
		// An exception rule beats any wildcard/exact rule.
		return strings.Join(labels[exceptionAt+1:], "."), labels
	}
	if best > len(labels) {
		best = len(labels)
	}
	return strings.Join(labels[len(labels)-best:], "."), labels
}

func gunzipBase64(encoded string) (string, error) {
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return "", err
	}
	defer zr.Close()
	// PSL text is well under a megabyte; the guard is defence in depth.
	plain, err := io.ReadAll(io.LimitReader(zr, 8<<20))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
