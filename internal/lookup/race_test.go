package lookup

import (
	"testing"

	"github.com/techjiang/Whois2Api/internal/model"
	"github.com/techjiang/Whois2Api/internal/parse"
)

// choose() ranks by evidence, and the raw payload follows the winner. When the
// winner has no payload of its own (RDAP 404 with an empty body), the sibling's
// payload is the only thing that makes the debug view useful.
func TestChooseRanksByEvidenceNotArrival(t *testing.T) {
	slowAuthoritative := channelResult{
		source: model.SourceRDAP, verdict: parse.OutcomeFound, millis: 900, raw: "record",
	}
	fastThrottled := channelResult{
		source: model.SourceWhoIs, verdict: parse.OutcomeRateLimited, millis: 40, raw: "rate limited",
	}
	got := choose([]channelResult{fastThrottled, slowAuthoritative}, false)
	if got.verdict != parse.OutcomeFound {
		t.Fatalf("verdict = %v, want found (evidence must beat latency)", got.verdict)
	}
	if got.raw != "record" {
		t.Fatalf("raw = %q, want the winning channel's payload", got.raw)
	}
}

func TestChoosePrefersWhoIsWhenAsked(t *testing.T) {
	a := channelResult{source: model.SourceRDAP, verdict: parse.OutcomeFound, millis: 100}
	b := channelResult{source: model.SourceWhoIs, verdict: parse.OutcomeFound, millis: 200}
	if got := choose([]channelResult{a, b}, false); got.source != model.SourceRDAP {
		t.Fatalf("default tie-break source = %v, want rdap", got.source)
	}
	if got := choose([]channelResult{a, b}, true); got.source != model.SourceWhoIs {
		t.Fatalf("W2A_WHOIS_FIRST tie-break source = %v, want whois", got.source)
	}
}

func TestTruncateRawBoundsThePayload(t *testing.T) {
	if got := truncateRaw("short"); got != "short" {
		t.Fatalf("truncateRaw(short) = %q", got)
	}
	long := make([]byte, maxRawPreview+500)
	for i := range long {
		long[i] = 'x'
	}
	if got := truncateRaw(string(long)); len(got) != maxRawPreview {
		t.Fatalf("len = %d, want %d", len(got), maxRawPreview)
	}
}
