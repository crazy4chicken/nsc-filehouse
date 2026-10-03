package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// MaxBodyBytes caps decoded JSON request bodies at 1 MiB.
const MaxBodyBytes int64 = 1 << 20

// ErrBodyTooLarge reports that a request body exceeded MaxBodyBytes.
var ErrBodyTooLarge = errors.New("request body too large")

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

// DecodeJSON decodes a size limited JSON request body into dst. The wrapped error
// is ErrBodyTooLarge when the limit was hit; every other failure is a caller
// error (invalid_request).
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fmt.Errorf("%w: limit is %d bytes", ErrBodyTooLarge, MaxBodyBytes)
		}
		return fmt.Errorf("invalid json body: %w", err)
	}
	return nil
}
