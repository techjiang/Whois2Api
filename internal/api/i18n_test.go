package api

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/asoe/whois2api/internal/model"
)

// noticeCatalogue is every caveat the engine and API can emit. A new notice
// code that nobody translated would reach a Chinese reader as English prose in
// the middle of a Chinese card, so the UI dictionary is checked against this
// list rather than trusted.
func noticeCatalogue() []model.Notice {
	return []model.Notice{
		model.NoticeRegistryWithheld,
		model.NoticeRateLimited,
		model.NoticeBlocked,
		model.NoticeDNSResolvesButAvailable,
		model.NoticeRegisteredWithoutDNS,
		model.NoticeUnknownButDNS,
		model.NoticeSubdomainParentAvailable,
		model.NoticeExpired,
		model.NoticeExpiresWithin7Days,
		model.NoticeExpiresWithin30Days,
		model.WarningStaleServed,
		model.WarningNoAnswerNoDNS,
		model.WarningCachedWithoutRaw,
		model.WarningNoUpstreamPayload,
	}
}

// Every notice code needs an entry in every language the UI ships. This is a
// lint, not a proof: it reads the dictionary as text because that is what the
// browser gets.
func TestEveryNoticeCodeIsTranslated(t *testing.T) {
	raw, err := fs.ReadFile(assetFS, "i18n.js")
	if err != nil {
		t.Fatalf("read i18n.js from embedded assets: %v", err)
	}
	for _, n := range noticeCatalogue() {
		if n.Code == "" || n.Text == "" {
			t.Errorf("notice %+v must carry both a code and fallback text", n)
			continue
		}
		// Two language blocks, so each key must appear at least twice.
		key := regexp.MustCompile(`'notice\.` + regexp.QuoteMeta(n.Code) + `':`)
		if got := len(key.FindAllStringIndex(string(raw), -1)); got < 2 {
			t.Errorf("notice %q is translated %d time(s) in web/i18n.js, want at least 2 (en + zh)", n.Code, got)
		}
	}
}

// Error codes are also a contract, and the UI translates on them. An error with
// no translation would surface the server's English prose in a Chinese card.
func TestEveryErrorCodeIsTranslated(t *testing.T) {
	raw, err := fs.ReadFile(assetFS, "i18n.js")
	if err != nil {
		t.Fatalf("read i18n.js: %v", err)
	}
	codes := []string{
		CodeInvalidDomain, CodeUnsupportedTLD, CodeUnauthorized,
		CodeRateLimited, CodeBadRequest, CodeTooManyItems,
		CodeUpstreamUnavailable, CodeInternal, CodeMethodNotAllowed,
	}
	for _, c := range codes {
		// Message and hint are separate strings, and both need translating:
		// an error that says "invalid domain" in Chinese and then explains
		// itself in English is worse than one that is simply English.
		for _, suffix := range []string{"", `\.hint`} {
			key := regexp.MustCompile(`'err\.` + regexp.QuoteMeta(c) + suffix + `':`)
			if got := len(key.FindAllStringIndex(string(raw), -1)); got < 2 {
				t.Errorf("error code %q%s is translated %d time(s) in web/i18n.js, want at least 2 (en + zh)", c, suffix, got)
			}
		}
	}
}

// Codes are the contract: they must be stable, lower_snake_case, and carry no
// wording that a copy edit would be tempted to change.
func TestNoticeCodesAreStableIdentifiers(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	seen := map[string]bool{}
	for _, n := range noticeCatalogue() {
		if !shape.MatchString(n.Code) {
			t.Errorf("notice code %q is not lower_snake_case", n.Code)
		}
		if seen[n.Code] {
			t.Errorf("duplicate notice code %q", n.Code)
		}
		seen[n.Code] = true
	}
}

// A language block that contains text from the other language is the classic
// copy-paste bug in a dictionary: "Cached 63 秒 ago" shipped in the English UI
// for exactly this reason. Catch it as a test rather than by squinting at a
// screenshot.
func TestDictionaryBlocksAreNotMixed(t *testing.T) {
	raw, err := fs.ReadFile(assetFS, "i18n.js")
	if err != nil {
		t.Fatalf("read i18n.js: %v", err)
	}
	cjk := regexp.MustCompile(`[\x{4e00}-\x{9fff}]`)
	// Split on the language block headers so each key can be attributed.
	blocks := map[string]string{}
	for _, lang := range []string{"en", "zh"} {
		start := regexp.MustCompile(`\n\s+` + lang + `: \{`).FindStringIndex(string(raw))
		if start == nil {
			t.Fatalf("language block %q not found in web/i18n.js", lang)
		}
		rest := string(raw)[start[1]:]
		end := regexp.MustCompile(`\n\s{4}\}`).FindStringIndex(rest)
		if end == nil {
			t.Fatalf("language block %q is not closed", lang)
		}
		blocks[lang] = rest[:end[0]]
	}
	// lang.other names the language you would switch *to*, so it is written in
	// that language in both blocks. Everything else must be monolingual.
	if cjk.MatchString(blocks["en"]) {
		for _, line := range regexp.MustCompile(`\n`).Split(blocks["en"], -1) {
			if cjk.MatchString(line) && !strings.Contains(line, "'lang.other'") {
				t.Errorf("English dictionary contains CJK text: %s", regexp.MustCompile(`\s+`).ReplaceAllString(line, " "))
			}
		}
	}
	if !cjk.MatchString(blocks["zh"]) {
		t.Error("Chinese dictionary contains no CJK text at all; did the keys get swapped?")
	}
}

// The raw-payload panel interpolates a channel name into a sentence
// ("Raw {source} response"). That placeholder must receive a translated token:
// passing the raw `whois`/`rdap` identifier through produced "原始 upstream 响应"
// in the Chinese UI — half a sentence in the wrong language, in a card that was
// otherwise fully Chinese.
func TestChannelNamesAreTranslated(t *testing.T) {
	raw, err := fs.ReadFile(assetFS, "i18n.js")
	if err != nil {
		t.Fatalf("read i18n.js: %v", err)
	}
	sources := []string{
		string(model.SourceRDAP), string(model.SourceWhoIs),
		string(model.SourceCache), "upstream", "none",
	}
	for _, src := range sources {
		key := regexp.MustCompile(`'source\.` + regexp.QuoteMeta(src) + `':`)
		if got := len(key.FindAllStringIndex(string(raw), -1)); got < 2 {
			t.Errorf("channel %q is translated %d time(s) in web/i18n.js, want at least 2 (en + zh)", src, got)
		}
	}
}

// The DNS probe measures the registrable domain, so a subdomain card must name
// that domain next to the answer. Otherwise "DNS resolves: no" under a
// subdomain heading reads as a claim about the subdomain.
func TestSubdomainDNSCaveatIsLabelled(t *testing.T) {
	raw, err := fs.ReadFile(assetFS, "i18n.js")
	if err != nil {
		t.Fatalf("read i18n.js: %v", err)
	}
	if got := regexp.MustCompile(`'field\.dns_of':`).FindAllStringIndex(string(raw), -1); len(got) < 2 {
		t.Fatalf("field.dns_of is translated %d time(s), want at least 2", len(got))
	}
}

// The raw-panel label is a whole sentence per source, not "{source}" glued into
// a template. Chinese needs no space around Latin script ("原始 RDAP 报文") but
// the space belongs inside each phrase, not in the template: a template of
// "原始 {source} 报文" renders "原始 上游 报文" for the upstream case, because
// that label is already a Chinese word.
func TestRawPanelLabelIsWrittenPerSource(t *testing.T) {
	raw, err := fs.ReadFile(assetFS, "i18n.js")
	if err != nil {
		t.Fatalf("read i18n.js: %v", err)
	}
	js := string(raw)
	if strings.Contains(js, "'raw.summary'") {
		// A generic template is allowed only if nothing interpolates {source}.
		if regexp.MustCompile(`'raw\.summary':\s*'[^']*\{source\}[^']*'`).MatchString(js) {
			t.Error("raw.summary still interpolates {source}; write one label per source instead")
		}
	}
	for _, src := range []string{"rdap", "whois", "upstream", "none"} {
		key := regexp.MustCompile(`'raw\.summary\.` + regexp.QuoteMeta(src) + `':`)
		if got := len(key.FindAllStringIndex(js, -1)); got < 2 {
			t.Errorf("raw.summary.%s is translated %d time(s), want at least 2 (en + zh)", src, got)
		}
	}
}
