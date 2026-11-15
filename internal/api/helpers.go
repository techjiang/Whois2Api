package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
)

// maxJSONBody bounds request bodies to keep memory use predictable.
const maxJSONBody = 64 << 10

// decodeJSONBody decodes a JSON body with strict limits.
func decodeJSONBody(r *http.Request, dst any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
		return errors.New("expected Content-Type: application/json")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("malformed JSON body")
	}
	// Reject trailing garbage so two payloads cannot be smuggled in one body.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected data after JSON body")
	}
	return nil
}

func isJSONContentType(ct string) bool {
	for i := 0; i < len(ct); i++ {
		if ct[i] == ';' {
			ct = ct[:i]
			break
		}
	}
	return trimSpace(ct) == "application/json"
}

func goVersion() string { return runtime.Version() }
