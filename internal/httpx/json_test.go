package httpx

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeJSONRejectsUnknownFields pins the strict body contract: a member the
// target struct does not define is reported with its name, so a handler can
// answer 400 with the offending field instead of silently dropping the value.
func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	type payload struct {
		Owner string `json:"owner"`
	}
	var target payload
	err := DecodeJSON(httptest.NewRecorder(),
		httptest.NewRequest("POST", "/api/v1/buckets/x", strings.NewReader(`{"owner":"alice","owner_id":"bob"}`)), &target)
	var unknown *UnknownFieldError
	if !errors.As(err, &unknown) {
		t.Fatalf("DecodeJSON error = %v, want *UnknownFieldError", err)
	}
	if unknown.Field != "owner_id" {
		t.Fatalf("unknown field = %q, want owner_id", unknown.Field)
	}
	if got, want := unknown.Error(), `unknown request field "owner_id"`; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

// TestDecodeJSONAcceptsOneDocument guards the strict decoder against rejecting
// valid payloads: trailing whitespace is not a second document.
func TestDecodeJSONAcceptsOneDocument(t *testing.T) {
	type payload struct {
		Owner string `json:"owner"`
	}
	var target payload
	err := DecodeJSON(httptest.NewRecorder(),
		httptest.NewRequest("POST", "/api/v1/buckets/x", strings.NewReader("{\"owner\":\"alice\"}\n")), &target)
	if err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if target.Owner != "alice" {
		t.Fatalf("owner = %q, want alice", target.Owner)
	}
}

// TestDecodeJSONRejectsTrailingDocument covers the other silent-truncation path:
// a body carrying a second JSON document is a caller error, not a request whose
// tail was ignored.
func TestDecodeJSONRejectsTrailingDocument(t *testing.T) {
	var target map[string]any
	err := DecodeJSON(httptest.NewRecorder(),
		httptest.NewRequest("POST", "/api/v1/buckets/x", strings.NewReader(`{"owner":"alice"}{"owner":"bob"}`)), &target)
	if err == nil {
		t.Fatal("DecodeJSON accepted a second JSON document")
	}
	var unknown *UnknownFieldError
	if errors.As(err, &unknown) {
		t.Fatalf("trailing data reported as %v, want a plain body error", err)
	}
}
