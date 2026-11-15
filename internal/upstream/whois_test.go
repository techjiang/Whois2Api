package upstream

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/techjiang/Whois2Api/internal/parse"
)

// fakeWhois starts a local server that replies with response per query.
func fakeWhois(t *testing.T, respond func(query string) string) (addr string, queries *[]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	seen := &[]string{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				q := strings.TrimSpace(string(buf[:n]))
				mu.Lock()
				*seen = append(*seen, q)
				mu.Unlock()
				_, _ = c.Write([]byte(respond(q)))
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return ln.Addr().String(), seen
}

func TestWhoIsQueryReturnsFoundRecord(t *testing.T) {
	addr, _ := fakeWhois(t, func(q string) string {
		return "Domain Name: EXAMPLE.COM\r\nRegistrar: Test Registrar\r\nCreation Date: 2020-01-02T03:04:05Z\r\n"
	})
	c := NewWhoIsClient(3 * time.Second)
	res := c.Query(context.Background(), addr, "example.com")
	if res.Outcome != parse.OutcomeFound {
		t.Fatalf("outcome = %v (%s), want found", res.Outcome, res.Evidence)
	}
	parsed := parse.ParseWhoIs(res.Raw)
	if parsed.Registrar != "Test Registrar" {
		t.Fatalf("registrar = %q", parsed.Registrar)
	}
}

func TestWhoIsQueryRetriesAlternateForm(t *testing.T) {
	// The server only understands the "-T dn,ace name" form.
	addr, queries := fakeWhois(t, func(q string) string {
		if strings.HasPrefix(q, "-T dn,ace ") {
			return "Domain: example.de\r\nStatus: connect\r\n"
		}
		return "" // unusable, forcing a retry
	})
	c := NewWhoIsClient(3 * time.Second)
	res := c.Query(context.Background(), addr, "example.de")
	if res.Outcome != parse.OutcomeFound {
		t.Fatalf("outcome = %v, want found after retry", res.Outcome)
	}
	if len(*queries) < 2 {
		t.Fatalf("expected a retry, saw %d queries: %v", len(*queries), *queries)
	}
}

func TestWhoIsQueryStopsOnRateLimit(t *testing.T) {
	addr, queries := fakeWhois(t, func(q string) string {
		return ">>> Your request has been rate limited. Please wait before retrying.\r\n"
	})
	c := NewWhoIsClient(3 * time.Second)
	res := c.Query(context.Background(), addr, "example.com")
	if res.Outcome != parse.OutcomeRateLimited {
		t.Fatalf("outcome = %v, want rate_limited", res.Outcome)
	}
	// Retrying a throttled server only makes things worse.
	if len(*queries) != 1 {
		t.Fatalf("expected exactly one query, saw %d", len(*queries))
	}
}

func TestWhoIsQueryHandlesConnectionFailure(t *testing.T) {
	c := NewWhoIsClient(500 * time.Millisecond)
	res := c.Query(context.Background(), "127.0.0.1:1", "example.com")
	if res.Err == nil {
		t.Fatal("expected a transport error")
	}
	if res.Outcome != parse.OutcomeUnusable {
		t.Fatalf("outcome = %v, want unusable", res.Outcome)
	}
}

func TestWhoIsQueryRespectsContextCancel(t *testing.T) {
	addr, _ := fakeWhois(t, func(q string) string {
		time.Sleep(2 * time.Second)
		return "Domain Name: LATE.COM\r\n"
	})
	c := NewWhoIsClient(5 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	res := c.Query(ctx, addr, "late.com")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancel took %v, expected a prompt return", elapsed)
	}
	if res.Err == nil && res.Outcome == parse.OutcomeFound {
		t.Log("server answered before cancel; acceptable")
	}
}

func TestWhoIsQueryCapsResponseSize(t *testing.T) {
	// A server that streams forever must not exhaust memory.
	addr, _ := fakeWhois(t, func(q string) string {
		return strings.Repeat("Domain Name: BIG.COM\r\n", 200000)
	})
	c := NewWhoIsClient(3 * time.Second)
	res := c.Query(context.Background(), addr, "big.com")
	if len(res.Raw) > maxWhoIsBody+len("Domain Name: BIG.COM\r\n") {
		t.Fatalf("response was not capped: %d bytes", len(res.Raw))
	}
}

func TestClassifyNetErrHidesInternals(t *testing.T) {
	err := classifyNetErr("whois", errors.New("dial tcp 10.0.0.1:43: connection refused"))
	if strings.Contains(err.Error(), "10.0.0.1") {
		t.Fatalf("error leaked an internal address: %v", err)
	}
}

func TestPreferredVariantLearnsAndSticks(t *testing.T) {
	c := NewWhoIsClient(time.Second)
	if got := c.preferredVariant("whois.example"); got != -1 {
		t.Fatalf("initial pref = %d, want -1 (unknown)", got)
	}
	c.rememberVariant("whois.example", 0)
	if got := c.preferredVariant("whois.example"); got != 0 {
		t.Fatalf("pref = %d, want 0 (first form learned)", got)
	}
}

func TestMeasuredPreferenceIsUsedFirst(t *testing.T) {
	// A server that answers only to "/e" must be reached on the first try.
	addr, queries := fakeWhois(t, func(q string) string {
		if strings.HasSuffix(q, "/e") {
			return "Domain Name: EXAMPLE.JP\r\nRegistrar: JPRS\r\n"
		}
		return ""
	})
	// Bind the measured preference to the fake server's host:port form.
	c := NewWhoIsClient(3 * time.Second)
	c.measuredPref = map[string]int{addr: 2}
	res := c.Query(context.Background(), addr, "example.jp")
	if res.Outcome != parse.OutcomeFound {
		t.Fatalf("outcome = %v, want found", res.Outcome)
	}
	if len(*queries) != 1 {
		t.Fatalf("expected the preferred form on the first try, saw %v", *queries)
	}
}

// TestLearnedVariantSurvivesReordering is a regression test for a real bug:
// the learned index was stored from the reordered slice, so after the first
// successful retry the server kept being queried with the wrong (slow) form.
func TestLearnedVariantSurvivesReordering(t *testing.T) {
	calls := 0
	addr, queries := fakeWhois(t, func(q string) string {
		calls++
		if strings.HasSuffix(q, "/e") {
			return "Domain Name: EXAMPLE.JP\r\nRegistrar: JPRS\r\n"
		}
		return ""
	})
	c := NewWhoIsClient(3 * time.Second)

	// First query discovers that form 2 ("%s/e") is the one that works.
	if res := c.Query(context.Background(), addr, "example.jp"); res.Outcome != parse.OutcomeFound {
		t.Fatalf("first query failed: %v", res.Outcome)
	}
	if got := c.preferredVariant(addr); got != 2 {
		t.Fatalf("learned variant = %d, want 2", got)
	}
	before := len(*queries)

	// Second query must go straight to the learned form.
	if res := c.Query(context.Background(), addr, "example.jp"); res.Outcome != parse.OutcomeFound {
		t.Fatalf("second query failed: %v", res.Outcome)
	}
	added := (*queries)[before:]
	if len(added) != 1 {
		t.Fatalf("second query made %d upstream calls (%v), want 1", len(added), added)
	}
	if !strings.HasSuffix(added[0], "/e") {
		t.Fatalf("second query used %q, want the learned /e form", added[0])
	}
	_ = calls
}
