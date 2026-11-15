package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// refusalOrUnknown reports outcomes that are honest "we could not tell"
// answers rather than a verdict about the domain.
func refusalOrUnknown(o Outcome) bool {
	return o == OutcomeRateLimited || o == OutcomeBlocked || o == OutcomeUnusable
}

// TestClassifyAgainstLiveCorpus runs the classifier over responses captured
// from production registry WHOIS servers. File names encode the ground truth:
// "<tld>.yes.txt" is a registered domain, "<tld>.no.txt" is one the registry
// explicitly reported as absent.
func TestClassifyAgainstLiveCorpus(t *testing.T) {
	files, err := filepath.Glob("../../testdata/whois/*.txt")
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files found: %v", err)
	}

	var (
		checked    int
		refused    int
		restricted int
		problems   []string
	)

	for _, path := range files {
		base := filepath.Base(path)
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", base, readErr)
		}
		text := string(raw)

		var want Outcome
		switch {
		case strings.HasSuffix(base, ".yes.txt"):
			want = OutcomeFound
		case strings.HasSuffix(base, ".no.txt"):
			want = OutcomeNotFound
		default:
			continue
		}
		checked++

		got, reason := Classify(text)
		switch {
		case refusalOrUnknown(got):
			// The live server really did refuse, or spoke a dialect we do not
			// model. "unknown" is the honest answer; it is never a wrong verdict.
			refused++
		case got == OutcomeRestricted:
			// Confirmed to exist but withheld: correct for a taken domain.
			restricted++
			if want != OutcomeFound {
				t.Errorf("%s: absent domain reported as restricted", base)
			}
		case got != want:
			// This is the dangerous class: a confident, wrong answer.
			problems = append(problems, base)
			t.Errorf("%s: got %s, want %s (evidence %q)\n--- head ---\n%s",
				base, got, want, reason, firstLines(text, 6))
		}
	}

	if checked < 100 {
		t.Fatalf("corpus too small: only %d samples", checked)
	}
	t.Logf("checked %d live samples: %d definitive, %d restricted, %d refused/unknown",
		checked, checked-refused-restricted, restricted, refused)
	if len(problems) > 0 {
		t.Fatalf("%d confident wrong verdicts: %v", len(problems), problems)
	}
}

// TestRefusalBeatsLegalFooter guards the highest-risk regression: long legal
// disclaimers mention rate limiting and "not permitted", but a real refusal
// only appears at the top of the response.
func TestRefusalBeatsLegalFooter(t *testing.T) {
	registeredWithFooter := `Domain Name: NIC.IO
Registry Domain ID: REDACTED
Creation Date: 2003-09-15T11:13:53Z
Registrar: Registry Operator acts as Registrar (9999)
Domain Status: serverDeleteProhibited

Terms of Use: Queries to the Whois services are rate limited. If too many
queries are received the service will begin to reject further queries.
It is not permitted to use this data for advertising.`
	if got, _ := Classify(registeredWithFooter); got != OutcomeFound {
		t.Fatalf("legal footer flipped a registered record to %s", got)
	}

	throttled := ">>> Your request has been rate limited. Please wait before retrying.\n"
	if got, _ := Classify(throttled); got != OutcomeRateLimited {
		t.Fatalf("throttled response classified as %s, want rate_limited", got)
	}
}

// TestHKRegisteredTrap covers a live .hk quirk: the registered record contains
// "not available for registration", which a substring check would flip.
func TestHKRegisteredTrap(t *testing.T) {
	taken := "This domain is currently not available for registration. Please select other domain.\n"
	if got, _ := Classify(taken); got != OutcomeRestricted {
		t.Fatalf(".hk reserved name classified as %s, want restricted", got)
	}
	// The genuinely-unused wording must still mean available.
	if got, _ := Classify("The domain has not been registered.\n"); got != OutcomeNotFound {
		t.Fatalf(".hk free name classified as %s, want not_found", got)
	}
	// .hk throttles with a bare opaque token.
	if got, _ := Classify("CMM174\n"); got != OutcomeRateLimited {
		t.Fatalf(".hk quota token classified as %s, want rate_limited", got)
	}
	absent := "The domain has not been registered.\n"
	if got, _ := Classify(absent); got != OutcomeNotFound {
		t.Fatalf(".hk absent record classified as %s", got)
	}
}

// TestRestrictedIsNotAvailable pins the .ca/.nz/.kr behaviour: they answer with
// an error code for names that exist but are withheld.
func TestRestrictedIsNotAvailable(t *testing.T) {
	body := "Error code: 01044\nError message: The domain name requested has usage restrictions applied to it.\n"
	got, _ := Classify(body)
	if got == OutcomeNotFound {
		t.Fatal("restricted .ca record flipped to available")
	}
	if got != OutcomeRestricted {
		t.Fatalf("got %s, want restricted", got)
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
