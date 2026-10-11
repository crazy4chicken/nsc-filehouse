package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// MaxBodyBytes caps decoded JSON request bodies at 1 MiB.
const MaxBodyBytes int64 = 1 << 20

// ErrBodyTooLarge reports that a request body exceeded MaxBodyBytes.
var ErrBodyTooLarge = errors.New("request body too large")

// UnknownFieldError reports a JSON member the target struct does not accept.
// Bodies are decoded strictly, so a misspelled or aliased member is a caller
// error instead of a silently ignored value.
type UnknownFieldError struct {
	Field string
}

func (e *UnknownFieldError) Error() string {
	return "unknown request field " + strconv.Quote(e.Field)
}

// WriteJSON marshals v and writes it with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		WriteProblem(w, nil, http.StatusInternalServerError, "", "service_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// DecodeJSON decodes a size limited JSON request body into dst. Decoding is
// strict: a member dst does not define is reported as *UnknownFieldError and a
// second JSON document in the body is rejected, so a handler never acts on a
// request it only partially understood. The wrapped error is ErrBodyTooLarge
// when the limit was hit; every other failure is a caller error
// (invalid_request).
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fmt.Errorf("%w: limit is %d bytes", ErrBodyTooLarge, MaxBodyBytes)
		}
		if field, ok := unknownField(err); ok {
			return &UnknownFieldError{Field: field}
		}
		return fmt.Errorf("invalid json body: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("invalid json body: trailing data after the JSON document")
	}
	return nil
}

// unknownFieldPrefix is how encoding/json reports a member the target struct
// does not define; the offending name follows as a JSON string.
const unknownFieldPrefix = "json: unknown field "

// unknownField extracts the offending member from the encoding/json error. The
// standard library reports it as an untyped error, so the name is recovered
// from the message.
func unknownField(err error) (string, bool) {
	message := err.Error()
	if !strings.HasPrefix(message, unknownFieldPrefix) {
		return "", false
	}
	var field string
	if err := json.Unmarshal([]byte(strings.TrimPrefix(message, unknownFieldPrefix)), &field); err != nil {
		return "", false
	}
	if field == "" {
		return "", false
	}
	return field, true
}
