package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/techjiang/Whois2Api/internal/parse"
)

const (
	// maxWhoIsBody bounds a single WHOIS response. Some servers stream very
	// long legal footers; 512 KiB is far beyond any real record.
	maxWhoIsBody = 512 << 10
	// maxSilentAttempts bounds retries against a server that accepts the
	// connection and then sends nothing at all until the read deadline.
	// .es and .pt behave this way for every query shape, so retrying just
	// burns the request budget.
	maxSilentAttempts = 1
	// whoisReadIdle is how long we wait for more bytes before deciding the
	// response is complete. WHOIS has no length prefix, so idle is the only
	// reliable end-of-response signal.
	whoisReadIdle = 1200 * time.Millisecond
)

// WhoIsClient performs raw port-43 queries.
type WhoIsClient struct {
	timeout time.Duration
	// dial lets tests substitute a fake server.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	mu   sync.Mutex
	// queryVariant remembers, per server, which query form produced a record,
	// so we only pay for a retry once.
	queryVariant map[string]int
	// measuredPref overrides measuredFormPrefs in tests.
	measuredPref map[string]int
}

// NewWhoIsClient builds a client with the given overall timeout.
func NewWhoIsClient(timeout time.Duration) *WhoIsClient {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &WhoIsClient{
		timeout:      timeout,
		dial:         dialer.DialContext,
		queryVariant: make(map[string]int),
	}
}

// SetDialer overrides the dialer (tests only).
func (c *WhoIsClient) SetDialer(d func(ctx context.Context, network, addr string) (net.Conn, error)) {
	c.dial = d
}

// WhoIsResponse is one WHOIS attempt result.
type WhoIsResponse struct {
	Outcome  parse.Outcome
	Evidence string
	Raw      string
	Millis   int64
	Err      error
	Attempts int
}

// queryForms are the query shapes registries expect. Most accept the bare
// domain; DENIC takes a type flag and JPRS accepts an "/e" suffix for English.
var queryForms = []string{"%s", "-T dn,ace %s", "%s/e"}

// measuredFormPrefs seeds the preferred query form per server from live
// measurements. It is pure latency and completeness tuning, not correctness:
// every form still falls back to the others if the server changes.
//
//	whois.jprs.jp  bare query answers in ~3.3s (JPRS runs a slow path);
//	               "/e" answers in ~0.24s with the same data.
//	whois.denic.de bare query returns only "Status: connect";
//	               "-T dn,ace" returns nameservers and DNSSEC keys.
var measuredFormPrefs = map[string]int{
	"whois.jprs.jp":  2,
	"whois.denic.de": 1,
}

// Query asks server about domain, retrying with alternate query forms when a
// server answers unusably (the shape of "did not understand you").
func (c *WhoIsClient) Query(ctx context.Context, server, asciiDomain string) WhoIsResponse {
	start := time.Now()
	server = strings.TrimSpace(strings.ToLower(server))
	if server == "" {
		return WhoIsResponse{Outcome: parse.OutcomeUnusable, Err: errors.New("whois: empty server")}
	}

	forms := queryForms
	var order []int
	pref := c.preferredVariant(server)
	if pref < 0 {
		// Nothing learned yet: start from the measured default if we have one.
		table := measuredFormPrefs
		if c.measuredPref != nil {
			table = c.measuredPref
		}
		pref = table[server]
	}
	if pref > 0 && pref < len(forms) {
		// Try the form that worked before first, keeping original indices so
		// the learned preference stays valid across reorderings.
		order = make([]int, 0, len(forms))
		order = append(order, pref)
		for i := range forms {
			if i != pref {
				order = append(order, i)
			}
		}
	} else {
		order = make([]int, len(forms))
		for i := range forms {
			order[i] = i
		}
	}

	attempts := 0
	silentReplies := 0
	var last WhoIsResponse
	for _, formIdx := range order {
		form := forms[formIdx]
		query := fmt.Sprintf(form, asciiDomain)
		attempts++
		raw, silent, err := c.exchange(ctx, server, query)
		if silent {
			silentReplies++
		}
		res := WhoIsResponse{Raw: raw, Attempts: attempts}
		if err != nil {
			res.Err = err
			last = res
			// Do not burn retries on a timeout or refused connection.
			break
		}
		outcome, evidence := parse.Classify(raw)
		res.Outcome = outcome
		res.Evidence = evidence
		if outcome == parse.OutcomeFound || outcome == parse.OutcomeNotFound ||
			outcome == parse.OutcomeRestricted {
			c.rememberVariant(server, formIdx)
			res.Millis = millisSince(start)
			return res
		}
		// Refusals will not improve with a different query form, and retrying
		// a throttled registry actively harms the install.
		if outcome == parse.OutcomeRateLimited || outcome == parse.OutcomeBlocked {
			res.Millis = millisSince(start)
			return res
		}
		// A server that accepted the connection and then said nothing for the
		// whole read window is unresponsive, not confused: another query form
		// will not help. A closed connection with no data is different and
		// still falls through to the next form.
		if silentReplies >= maxSilentAttempts {
			break
		}
		last = res
	}
	last.Millis = millisSince(start)
	last.Attempts = attempts
	return last
}

// exchange performs one request/response cycle on a fresh connection. The
// second return value reports whether the server accepted the request and then
// stayed silent until the read deadline (as opposed to closing the connection).
func (c *WhoIsClient) exchange(ctx context.Context, server, query string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Port 43 is implied; allow an explicit host:port for testing.
	addr := server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(server, "43")
	}

	conn, err := c.dial(ctx, "tcp", addr)
	if err != nil {
		return "", false, classifyNetErr("whois", err)
	}
	defer conn.Close()

	// Ensure a hung server cannot outlive the context.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", false, fmt.Errorf("whois: write query: %w", err)
	}

	var buf strings.Builder
	readBuf := make([]byte, 8<<10)
	sawData := false
	sawIdleTimeout := false
	for {
		// Reset the read deadline to allow a short idle window per chunk.
		if err := conn.SetReadDeadline(time.Now().Add(whoisReadIdle)); err != nil {
			break
		}
		n, readErr := conn.Read(readBuf)
		if n > 0 {
			// Trim the final chunk so the total never exceeds the cap.
			remaining := maxWhoIsBody - buf.Len()
			if n > remaining {
				buf.Write(readBuf[:remaining])
				break
			}
			buf.Write(readBuf[:n])
			sawData = true
		}
		if readErr != nil {
			// EOF and per-chunk idle timeouts both mean "response finished".
			var netErr net.Error
			if errors.Is(readErr, io.EOF) {
				break
			}
			if errors.As(readErr, &netErr) && netErr.Timeout() {
				sawIdleTimeout = true
				break
			}
			if errors.Is(readErr, context.DeadlineExceeded) {
				sawIdleTimeout = true
				break
			}
			return buf.String(), false, fmt.Errorf("whois: read: %w", readErr)
		}
	}
	// Silence means: the server took the query, sent nothing, and we gave up
	// waiting. That is a dead endpoint for this query, not a dialect mismatch.
	silent := sawIdleTimeout && !sawData
	return buf.String(), silent, nil
}

// preferredVariant returns the learned form index, or -1 when nothing has been
// learned yet. Storing the index directly keeps "form 0 worked" distinct from
// "unknown", which a zero value could not express.
func (c *WhoIsClient) preferredVariant(server string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.queryVariant[server]; ok {
		return v
	}
	return -1
}

func (c *WhoIsClient) rememberVariant(server string, idx int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Never let the map grow unbounded: servers are a small, fixed set.
	if len(c.queryVariant) > 4096 {
		c.queryVariant = make(map[string]int)
	}
	c.queryVariant[server] = idx
}
