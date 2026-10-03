package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
	"github.com/crazy4chicken/nsc-filehouse/internal/id"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// HeaderIdempotencyKey names the client supplied idempotency key.
const HeaderIdempotencyKey = "Idempotency-Key"

// HeaderIdempotencyReplayed marks a replayed response.
const HeaderIdempotencyReplayed = "Idempotency-Replayed"

const (
	maxIdempotencyKeyBytes = 1024
	maxRetainedResponse    = 64 << 10
	defaultIdempotencyTTL  = 24 * time.Hour
)

// Recover turns panics into RFC 9457 responses. A partially written response is
// logged but left untouched.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := &statusRecorder{ResponseWriter: w}
			defer func() {
				recovered := recover()
				if recovered == nil {
					return
				}
				// RequestID runs inside Recover, so the id lives on the response
				// header by the time a panic unwinds through here.
				requestID := httpx.RequestIDFromContext(r)
				if requestID == "" {
					requestID = recorder.Header().Get(httpx.HeaderRequestID)
				}
				log.Error("panic recovered",
					"panic", recovered,
					"method", r.Method,
					"path", r.URL.Path,
					"request_id", requestID,
					"stack", string(debug.Stack()))
				if recorder.status == 0 {
					httpx.WriteProblem(recorder, r, http.StatusInternalServerError, "", "service_unavailable")
				}
			}()
			next.ServeHTTP(recorder, r)
		})
	}
}

// RequestID assigns every request a request id, honouring a sane incoming
// X-Request-ID, and mirrors it on the response and in the request context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := sanitizeRequestID(r.Header.Get(httpx.HeaderRequestID))
		if requestID == "" {
			requestID = id.New()
		}
		w.Header().Set(httpx.HeaderRequestID, requestID)
		next.ServeHTTP(w, r.WithContext(httpx.WithRequestID(r.Context(), requestID)))
	})
}

// AccessLog emits one structured line per request.
func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx, slot := httpx.EnsureClientIPSlot(r.Context())
			recorder := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(recorder, r.WithContext(ctx))

			status := recorder.Status()
			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", status,
				"bytes", recorder.written,
				"duration_ms", time.Since(start).Milliseconds(),
			}
			if slot.IP != "" {
				attrs = append(attrs, "client_ip", slot.IP)
			}
			if requestID := httpx.RequestIDFromContext(r); requestID != "" {
				attrs = append(attrs, "request_id", requestID)
			}
			if status >= http.StatusInternalServerError {
				log.Error("http request", attrs...)
				return
			}
			log.Info("http request", attrs...)
		})
	}
}

// ClientIP resolves the client IP once per request and exposes it to handlers
// and to the access log through the request context.
func ClientIP(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, slot := httpx.EnsureClientIPSlot(r.Context())
			ip := httpx.ClientIP(r, trusted)
			slot.IP = ip
			next.ServeHTTP(w, r.WithContext(httpx.WithClientIP(ctx, ip)))
		})
	}
}

// Idempotency implements the Idempotency-Key contract for POST requests. The
// key is scoped to the raw Authorization header (else the client IP), the body
// fingerprint is checked, replays answer with Idempotency-Replayed: true, an in
// flight request yields 409 idempotency_in_progress and a different body 422
// idempotency_conflict. Requests or responses above 64 KiB and responses with
// status >= 429 are never retained.
func Idempotency(st store.IdempotencyStore, ttl time.Duration) func(http.Handler) http.Handler {
	if ttl <= 0 {
		ttl = defaultIdempotencyTTL
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if st == nil || r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.TrimSpace(r.Header.Get(HeaderIdempotencyKey))
			if key == "" || len(key) > maxIdempotencyKeyBytes {
				next.ServeHTTP(w, r)
				return
			}
			prefix, oversized, err := readPrefix(r.Body, maxRetainedResponse)
			if err != nil {
				httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
				return
			}
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))
			if oversized {
				next.ServeHTTP(w, r)
				return
			}

			scope := idempotencyScope(r)
			fingerprint := fingerprintRequest(r, prefix)
			now := time.Now()
			record, found, err := st.GetIdempotent(r.Context(), scope, key)
			if err != nil {
				httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
				return
			}
			if found && record.Status != store.IdemStatusDead && now.Sub(record.CreatedAt) < ttl {
				if record.Fingerprint != fingerprint {
					httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "", "idempotency_conflict")
					return
				}
				if record.Status == store.IdemStatusPending {
					httpx.WriteProblem(w, r, http.StatusConflict, "", "idempotency_in_progress")
					return
				}
				replayResponse(w, record)
				return
			}

			claimed, err := st.ClaimIdempotent(r.Context(), scope, key, fingerprint, now.Add(-ttl))
			if err != nil {
				httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
				return
			}
			if !claimed {
				// Another request owns the key: distinguish a conflicting body
				// from a request that is still running.
				current, currentFound, err := st.GetIdempotent(r.Context(), scope, key)
				if err != nil {
					httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
					return
				}
				if currentFound && current.Fingerprint != fingerprint {
					httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "", "idempotency_conflict")
					return
				}
				httpx.WriteProblem(w, r, http.StatusConflict, "", "idempotency_in_progress")
				return
			}

			recorder := &captureRecorder{statusRecorder: &statusRecorder{ResponseWriter: w}, limit: maxRetainedResponse}
			completed := false
			defer func() {
				// A panic unwinds through this middleware: release the key so the
				// client may retry instead of waiting for the record to expire.
				if !completed {
					markDead(st, r, scope, key, fingerprint)
				}
			}()
			next.ServeHTTP(recorder, r)
			completed = true

			status := recorder.Status()
			if recorder.overflow || status < http.StatusOK || status >= 429 {
				markDead(st, r, scope, key, fingerprint)
				return
			}
			// A failed write only costs the next caller a re-execution.
			_ = st.PutIdempotent(context.WithoutCancel(r.Context()), store.IdempotencyRecord{
				Scope:       scope,
				Key:         key,
				Fingerprint: fingerprint,
				Status:      status,
				Response:    encodeEnvelope(recorder.Header().Get("Content-Type"), recorder.body),
			})
		})
	}
}

func sanitizeRequestID(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || len(candidate) > 128 {
		return ""
	}
	for i := range len(candidate) {
		if char := candidate[i]; char < 0x21 || char > 0x7e {
			return ""
		}
	}
	return candidate
}

// readPrefix reads at most limit bytes and reports whether the reader holds more.
func readPrefix(body io.Reader, limit int) ([]byte, bool, error) {
	buffer := make([]byte, 0, 4096)
	chunk := make([]byte, 32<<10)
	for len(buffer) <= limit {
		n, err := body.Read(chunk)
		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
		}
		if err == io.EOF {
			return buffer, false, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
	return buffer, true, nil
}

func idempotencyScope(r *http.Request) string {
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		sum := sha256.Sum256([]byte(authorization))
		return "auth:" + hex.EncodeToString(sum[:])
	}
	return "ip:" + httpx.ClientIPFromContext(r)
}

func fingerprintRequest(r *http.Request, body []byte) string {
	hasher := sha256.New()
	hasher.Write([]byte(r.Method))
	hasher.Write([]byte{'\n'})
	hasher.Write([]byte(r.URL.RequestURI()))
	hasher.Write([]byte{'\n'})
	hasher.Write(body)
	return hex.EncodeToString(hasher.Sum(nil))
}

func replayResponse(w http.ResponseWriter, record store.IdempotencyRecord) {
	contentType, payload := decodeEnvelope(record.Response)
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.Header().Set(HeaderIdempotencyReplayed, "true")
	w.WriteHeader(record.Status)
	_, _ = w.Write(payload)
}

func markDead(st store.IdempotencyStore, r *http.Request, scope, key, fingerprint string) {
	_ = st.PutIdempotent(context.WithoutCancel(r.Context()), store.IdempotencyRecord{
		Scope:       scope,
		Key:         key,
		Fingerprint: fingerprint,
		Status:      store.IdemStatusDead,
		Response:    []byte{},
	})
}

// encodeEnvelope stores the response content type and body as
// "<content-type>\n<body>"; content types never contain a newline.
func encodeEnvelope(contentType string, body []byte) []byte {
	envelope := make([]byte, 0, len(contentType)+1+len(body))
	envelope = append(envelope, contentType...)
	envelope = append(envelope, '\n')
	return append(envelope, body...)
}

func decodeEnvelope(envelope []byte) (string, []byte) {
	if newline := bytes.IndexByte(envelope, '\n'); newline >= 0 {
		return string(envelope[:newline]), envelope[newline+1:]
	}
	return "", envelope
}

// statusRecorder records the status code and the number of bytes written.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

// Status returns the response status, defaulting to 200.
func (w *statusRecorder) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(body)
	w.written += int64(n)
	return n, err
}

func (w *statusRecorder) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap keeps http.ResponseController features working (ServeContent ranges).
func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// captureRecorder records up to limit response bytes for idempotent replay.
type captureRecorder struct {
	*statusRecorder
	limit    int
	body     []byte
	overflow bool
}

func (c *captureRecorder) Write(body []byte) (int, error) {
	if !c.overflow {
		if len(c.body)+len(body) > c.limit {
			c.overflow = true
			c.body = nil
		} else {
			c.body = append(c.body, body...)
		}
	}
	return c.statusRecorder.Write(body)
}

func (c *captureRecorder) Flush() {
	c.statusRecorder.Flush()
}

func (c *captureRecorder) Unwrap() http.ResponseWriter {
	return c.statusRecorder.ResponseWriter
}
