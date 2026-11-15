// Package upstream talks to the authoritative registry protocols.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/asoe/whois2api/internal/parse"
)

// maxRDAPBody bounds how much of an RDAP response we read. Real documents are
// a few kilobytes; anything beyond this is a misbehaving server or an attack.
const maxRDAPBody = 2 << 20 // 2 MiB

// RDAPClient queries an RDAP base URL for a domain.
type RDAPClient struct {
	http    *http.Client
	timeout time.Duration
}

// NewRDAPClient builds a client with a bounded, keep-alive-friendly transport.
func NewRDAPClient(timeout time.Duration) *RDAPClient {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		// Registries serve small JSON documents; gzip cuts transfer time.
		DisableCompression: false,
	}
	return &RDAPClient{
		http:    &http.Client{Transport: transport, Timeout: timeout},
		timeout: timeout,
	}
}

// RDAPResponse is one RDAP attempt result.
type RDAPResponse struct {
	Result     parse.RDAPResult
	Millis     int64
	HTTPStatus int
	Err        error
}

// Query fetches base+domain and parses it. base must end with "/".
func (c *RDAPClient) Query(ctx context.Context, base, asciiDomain string) RDAPResponse {
	start := time.Now()
	url := strings.TrimSuffix(base, "/") + "/domain/" + asciiDomain

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return RDAPResponse{Err: fmt.Errorf("rdap: build request: %w", err), Millis: millisSince(start)}
	}
	// Ask for RDAP explicitly; some registries content-negotiate.
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.9")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return RDAPResponse{Err: classifyNetErr("rdap", err), Millis: millisSince(start)}
	}
	defer func() {
		// Drain a little so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRDAPBody))
	if err != nil {
		return RDAPResponse{HTTPStatus: resp.StatusCode, Err: fmt.Errorf("rdap: read body: %w", err), Millis: millisSince(start)}
	}

	// A 5xx is a server-side problem, not a statement about the domain.
	if resp.StatusCode >= 500 {
		return RDAPResponse{
			HTTPStatus: resp.StatusCode,
			Result:     parse.RDAPResult{Verdict: parse.OutcomeUnusable, Reason: fmt.Sprintf("RDAP HTTP %d", resp.StatusCode)},
			Millis:     millisSince(start),
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return RDAPResponse{
			HTTPStatus: resp.StatusCode,
			Result:     parse.RDAPResult{Verdict: parse.OutcomeRateLimited, Reason: "RDAP HTTP 429"},
			Millis:     millisSince(start),
		}
	}

	return RDAPResponse{
		Result:     parse.ParseRDAP(body, resp.StatusCode),
		HTTPStatus: resp.StatusCode,
		Millis:     millisSince(start),
	}
}

func millisSince(t time.Time) int64 { return time.Since(t).Milliseconds() }

// classifyNetErr turns transport failures into short, non-leaky messages.
func classifyNetErr(prefix string, err error) error {
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Errorf("%s: timeout", prefix)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: canceled", prefix)
	default:
		return fmt.Errorf("%s: transport error", prefix)
	}
}

const userAgent = "whois2api/1.0 (+https://github.com/asoe/whois2api)"
