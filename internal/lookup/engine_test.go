package lookup

import (
	"errors"
	"strings"
	"testing"

	"github.com/asoe/whois2api/internal/tld"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	psl := tld.MustDefault()
	table, err := tld.EmbeddedTable()
	if err != nil {
		t.Fatalf("embedded table: %v", err)
	}
	return New(psl, table, Options{
		RDAPTimeout:  1e9,
		WhoIsTimeout: 1e9,
		TotalTimeout: 2e9,
	})
}

func TestPrepareSubdomainReducesToRegistrableDomain(t *testing.T) {
	e := testEngine(t)
	cases := []struct {
		in            string
		wantQuery     string
		wantSubdomain string
	}{
		{"example.com", "example.com", ""},
		{"WWW.Example.COM", "example.com", "example.com"},
		{"a.b.c.example.co.uk", "example.co.uk", "example.co.uk"},
		{"example.co.uk.", "example.co.uk", ""},
		{"github.io", "github.io", ""},
		// A private-section suffix: "foo.github.io" is an eTLD+1 under PSL.
		{"foo.github.io", "foo.github.io", ""},
		{"中国.cn", "xn--fiqs8s.cn", ""},
	}
	for _, c := range cases {
		got, err := e.Prepare(c.in)
		if err != nil {
			t.Errorf("Prepare(%q) error: %v", c.in, err)
			continue
		}
		if got.Query != c.wantQuery {
			t.Errorf("Prepare(%q).Query = %q, want %q", c.in, got.Query, c.wantQuery)
		}
		if got.SubdomainOf != c.wantSubdomain {
			t.Errorf("Prepare(%q).SubdomainOf = %q, want %q", c.in, got.SubdomainOf, c.wantSubdomain)
		}
	}
}

func TestPrepareRejectsInvalidInput(t *testing.T) {
	e := testEngine(t)
	bad := []string{
		"", "   ", "com", "localhost", "a..b", ".", "-", "..com",
		"example.com/evil", "example.com:8080", "http://example.com",
		"exa mple.com", strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 130) + "com",
	}
	for _, in := range bad {
		if _, err := e.Prepare(in); !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("Prepare(%q) error = %v, want ErrInvalidDomain", in, err)
		}
	}
}

func TestPrepareAcceptsPunycodeAndUnicode(t *testing.T) {
	e := testEngine(t)
	pairs := [][2]string{
		{"中国.cn", "xn--fiqs8s.cn"},
		{"xn--fiqs8s.cn", "xn--fiqs8s.cn"},
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"例え.テスト", "xn--r8jz45g.xn--zckzah"},
	}
	for _, p := range pairs {
		got, err := e.Prepare(p[0])
		if err != nil {
			t.Errorf("Prepare(%q) error: %v", p[0], err)
			continue
		}
		if got.ASCII != p[1] {
			t.Errorf("Prepare(%q).ASCII = %q, want %q", p[0], got.ASCII, p[1])
		}
	}
}

func TestRouteForKnownAndUnknownTLD(t *testing.T) {
	e := testEngine(t)
	tgt, err := e.Prepare("example.com")
	if err != nil {
		t.Fatal(err)
	}
	route, err := e.Route(tgt)
	if err != nil {
		t.Fatalf("Route(com): %v", err)
	}
	if route.WhoIs == "" && len(route.RDAP) == 0 {
		t.Fatal("com has no route")
	}

	tgt, err = e.Prepare("example.zzzz-not-a-tld")
	if err != nil {
		t.Fatalf("Prepare should accept syntactically valid names: %v", err)
	}
	if _, err := e.Route(tgt); !errors.Is(err, ErrUnsupportedTLD) {
		t.Fatalf("Route(unknown) error = %v, want ErrUnsupportedTLD", err)
	}
}
