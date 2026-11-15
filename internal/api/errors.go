package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// Error codes are stable strings so clients can branch on them without parsing
// prose.
const (
	CodeInvalidDomain       = "invalid_domain"
	CodeUnsupportedTLD      = "unsupported_tld"
	CodeNotFound            = "not_found"
	CodeUnauthorized        = "unauthorized"
	CodeRateLimited         = "rate_limited"
	CodeBadRequest          = "bad_request"
	CodeTooManyItems        = "too_many_items"
	CodeUpstreamUnavailable = "upstream_unavailable"
	CodeInternal            = "internal_error"
	CodeMethodNotAllowed    = "method_not_allowed"
)

// apiError is the single error envelope every failure uses.
type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		// Hint is actionable advice, shown in the UI as a tip.
		Hint string `json:"hint,omitempty"`
	} `json:"error"`
}

// writeError emits a JSON error with the given status.
func writeError(w http.ResponseWriter, status int, code, message, hint string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = message
	e.Error.Hint = hint
	writeJSON(w, status, e)
}

// writeJSON serializes v with a stable content type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Never let an intermediary cache an API answer keyed only by URL: the
	// response depends on tokens and rate limiting.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// The status line is already sent; log instead of corrupting the body.
		slog.Error("failed to encode response", "error", err)
	}
}

// asAPIError maps engine errors to HTTP responses.
func asAPIError(err error) (status int, code, message, hint string) {
	var domainErr *DomainError
	switch {
	case errors.As(err, &domainErr):
		return domainErr.Status, domainErr.Code, domainErr.Message, domainErr.Hint
	default:
		return http.StatusInternalServerError, CodeInternal,
			"Something went wrong while handling the request.",
			"If this persists, check the server logs."
	}
}

// DomainError is an error that carries its own HTTP mapping.
type DomainError struct {
	Status  int
	Code    string
	Message string
	Hint    string
	Err     error
}

func (e *DomainError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *DomainError) Unwrap() error { return e.Err }
