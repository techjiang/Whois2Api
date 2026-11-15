package lookup

import (
	"errors"
	"strings"
	"testing"

	"github.com/techjiang/Whois2Api/internal/model"
	"github.com/techjiang/Whois2Api/internal/tld"
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

// A name below a vendor-managed suffix sits outside the registry's authority,
// so the registry's "no match" must not become `available`. Verisign really
// does answer `No match for "FOO.UK.COM"`; the name is simply not Verisign's to
// sell.
func TestPrivateSuffixIsNotAvailability(t *testing.T) {
	e := testEngine(t)
	cases := []struct {
		in      string
		private bool
	}{
		{"foo.uk.com", true},
		{"a.b.github.io", true},
		{"uk.com", false},    // the suffix itself has a real record
		{"github.io", false}, // same
		{"example.com", false},
		{"example.co.uk", false},
	}
	for _, c := range cases {
		target, err := e.Prepare(c.in)
		if err != nil {
			t.Fatalf("Prepare(%q): %v", c.in, err)
		}
		if target.PrivateSuffix != c.private {
			t.Errorf("Prepare(%q).PrivateSuffix = %v, want %v", c.in, target.PrivateSuffix, c.private)
		}
	}

	// The rewrite itself lives in present(), so it applies to cold and warm
	// answers alike: an `available` verdict for such a name becomes `unknown`,
	// and the caller is told why.
	target, err := e.Prepare("foo.uk.com")
	if err != nil {
		t.Fatal(err)
	}
	available := present(&model.Domain{
		Verdict: model.VerdictAvailable, Confidence: model.ConfidenceStrong, Source: model.SourceWhoIs,
	}, target)
	if available.Verdict != model.VerdictUnknown {
		t.Errorf("verdict = %q, want unknown", available.Verdict)
	}
	if !hasNotice(available.Alerts, model.NoticePrivateSuffix.Code) {
		t.Errorf("alerts = %+v, want %q", available.Alerts, model.NoticePrivateSuffix.Code)
	}

	// It must not touch a genuinely authoritative answer.
	registered := present(&model.Domain{
		Verdict: model.VerdictRegistered, Confidence: model.ConfidenceStrong,
	}, target)
	if registered.Verdict != model.VerdictRegistered {
		t.Errorf("verdict = %q, want registered to survive", registered.Verdict)
	}

	// And a plain .com name is untouched either way.
	plain, err := e.Prepare("example.com")
	if err != nil {
		t.Fatal(err)
	}
	free := present(&model.Domain{Verdict: model.VerdictAvailable, Confidence: model.ConfidenceStrong}, plain)
	if free.Verdict != model.VerdictAvailable {
		t.Errorf("example.com verdict = %q, want available to survive", free.Verdict)
	}
	if hasNotice(free.Alerts, model.NoticePrivateSuffix.Code) {
		t.Error("example.com must not carry the private-suffix caveat")
	}
}

func hasNotice(list []model.Notice, code string) bool {
	for _, n := range list {
		if n.Code == code {
			return true
		}
	}
	return false
}
