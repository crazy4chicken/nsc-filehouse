// Package httpx holds the transport level helpers shared by every HTTP handler:
// RFC 9457 problem documents, request identifiers, opaque cursors, JSON helpers
// and trusted client IP resolution.
package httpx

import (
	"context"
	"encoding/json"
	"net/http"
)

// ContentTypeProblemJSON is the media type of RFC 9457 problem documents.
const ContentTypeProblemJSON = "application/problem+json"

// HeaderRequestID carries the request identifier in requests and responses.
const HeaderRequestID = "X-Request-ID"

// Problem is an RFC 9457 problem detail document. Detail carries a stable error
// code (see the service contract §6), Instance carries the request id.
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

type requestIDKey struct{}

// WithRequestID returns a context carrying the request identifier.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext returns the request identifier, or "" when unset.
func RequestIDFromContext(r *http.Request) string {
	if r == nil {
		return ""
	}
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}

// WriteProblemReason writes a problem document with an extra "reason" member.
//
// Handlers use it for authorization failures: detail stays the stable error code
// required by the service contract, while reason names the permission keys that
// were attempted. It never carries credentials.
func WriteProblemReason(w http.ResponseWriter, r *http.Request, status int, title, detail, reason string) {
	if title == "" {
		title = http.StatusText(status)
	}
	problem := struct {
		Problem
		Reason string `json:"reason,omitempty"`
	}{
		Problem: Problem{
			Type:     "about:blank",
			Title:    title,
			Status:   status,
			Detail:   detail,
			Instance: RequestIDFromContext(r),
		},
		Reason: reason,
	}
	body, err := json.Marshal(problem)
	if err != nil {
		body = []byte(`{"type":"about:blank","title":"Internal Server Error","status":500}`)
	}
	w.Header().Set("Content-Type", ContentTypeProblemJSON)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if r != nil && r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// WriteProblem writes an RFC 9457 problem document. Title defaults to the status
// text and detail is the stable error code from the service contract.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	if title == "" {
		title = http.StatusText(status)
	}
	problem := Problem{
		Type:     "about:blank",
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: RequestIDFromContext(r),
	}
	body, err := json.Marshal(problem)
	if err != nil {
		body = []byte(`{"type":"about:blank","title":"Internal Server Error","status":500}`)
	}
	w.Header().Set("Content-Type", ContentTypeProblemJSON)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if r != nil && r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}
