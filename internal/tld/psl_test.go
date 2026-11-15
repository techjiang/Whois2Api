package tld

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The publicsuffix.org reference test suite is the ground truth for the PSL
// algorithm. It lives in testdata so the test runs offline.
func TestPublicSuffixReferenceSuite(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/psl_test.txt")
	if err != nil {
		t.Fatalf("read reference suite: %v", err)
	}
	list := MustDefault()
	cases := parseReferenceSuite(t, string(raw))
	if len(cases) < 50 {
		t.Fatalf("reference suite parsed too few cases: %d", len(cases))
	}
	for _, c := range cases {
		if c.Input == nil {
			continue // null input is handled by the caller's validation layer
		}
		ascii, normErr := Normalize(*c.Input)
		if c.Expected == nil {
			if normErr == nil && list.RegistrableDomain(ascii) != "" {
				t.Errorf("RegistrableDomain(%q) = %q, want none", *c.Input, list.RegistrableDomain(ascii))
			}
			continue
		}
		if normErr != nil {
			t.Errorf("Normalize(%q) unexpected error: %v", *c.Input, normErr)
			continue
		}
		got := list.RegistrableDomain(ascii)
		// The suite states expectations in the input's own script; compare in
		// the canonical ASCII form this package operates on.
		want, wantErr := Normalize(*c.Expected)
		if wantErr != nil {
			t.Fatalf("Normalize(%q) failed while computing expectation: %v", *c.Expected, wantErr)
		}
		if got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q (ascii of %q)", *c.Input, got, want, *c.Expected)
		}
	}
}

type pslCase struct {
	Input    *string
	Expected *string
}

var pslCallRe = regexp.MustCompile(`(?m)^\s*checkPublicSuffix\((.+)\);\s*$`)

func parseReferenceSuite(t *testing.T, src string) []pslCase {
	t.Helper()
	var out []pslCase
	for _, m := range pslCallRe.FindAllStringSubmatch(src, -1) {
		args := splitArgs(m[1])
		if len(args) != 2 {
			t.Fatalf("bad reference line: %s", m[1])
		}
		out = append(out, pslCase{Input: parseArg(args[0]), Expected: parseArg(args[1])})
	}
	return out
}

func splitArgs(s string) []string {
	var parts []string
	depth := 0
	inStr := false
	cur := strings.Builder{}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && (i == 0 || s[i-1] != '\\'):
			inStr = !inStr
			cur.WriteByte(c)
		case inStr:
			cur.WriteByte(c)
		case c == ',' && depth == 0:
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			if c == '(' {
				depth++
			}
			if c == ')' {
				depth--
			}
			cur.WriteByte(c)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		parts = append(parts, strings.TrimSpace(cur.String()))
	}
	return parts
}

func parseArg(s string) *string {
	s = strings.TrimSpace(s)
	if s == "null" {
		return nil
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		v, err := strconv.Unquote(`"` + strings.ReplaceAll(s[1:len(s)-1], `"`, `\"`) + `"`)
		if err != nil {
			v = s[1 : len(s)-1]
		}
		return &v
	}
	return &s
}
