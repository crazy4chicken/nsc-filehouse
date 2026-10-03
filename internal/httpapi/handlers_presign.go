package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crazy4chicken/nsc-filehouse/internal/config"
	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
	"github.com/crazy4chicken/nsc-filehouse/internal/presign"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

const (
	// verbShare is the permission action required to mint a presigned URL.
	verbShare = "share"

	// maxPresignContentTypeBytes bounds the content type embedded into a token
	// so it can always be written back as an HTTP header.
	maxPresignContentTypeBytes = 255
)

// presignMintRequest is the JSON body of POST /api/v1/presign.
type presignMintRequest struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	Method      string `json:"method"`
	TTLSeconds  int64  `json:"ttl_seconds"`
	ContentType string `json:"content_type"`
	MaxBytes    int64  `json:"max_bytes"`
}

// presignMintResponse is the JSON body returned by POST /api/v1/presign. The
// expiry is the token's real expiry, truncated to whole seconds because the
// signature stores Unix seconds.
type presignMintResponse struct {
	URL       string    `json:"url"`
	Method    string    `json:"method"`
	Bucket    string    `json:"bucket"`
	Key       string    `json:"key"`
	ExpiresAt time.Time `json:"expires_at"`
}

// handlePresignMint mints a presigned URL for one object.
//
// Minting requires the share grant AND the grant the URL itself will exercise
// (read for GET/HEAD, write for PUT), both evaluated against the same
// bucket-derived resource context: a subject that may share a bucket it cannot
// read must not be able to hand out read URLs, and a write URL must never be
// minted by a subject without write access. The signed payload embeds
// subject/kind/team/perm_ver so redemption re-checks the effective permissions
// after they change.
func (s *Server) handlePresignMint(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	signer := s.Signer()
	if signer == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	var req presignMintRequest
	if !decodeRequestBody(w, r, &req) {
		return
	}
	req.Bucket = strings.TrimSpace(req.Bucket)
	req.ContentType = strings.TrimSpace(req.ContentType)
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	verb := ""
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		verb = verbRead
	case http.MethodPut:
		verb = verbWrite
	default:
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	if err := validateBucketName(req.Bucket); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_bucket_name")
		return
	}
	if err := validateObjectKey(req.Key); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_key")
		return
	}
	if req.TTLSeconds < 0 || req.MaxBytes < 0 || !validPresignContentType(req.ContentType) {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	ttl, ok := s.presignTTL(req.TTLSeconds)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	bucket, ok := s.bucketByName(w, r, req.Bucket)
	if !ok {
		return
	}
	attrs := map[string]any{"key": req.Key}
	if verb == verbWrite {
		attrs["content_type"] = req.ContentType
		attrs["uploader"] = claims.Subject
	}
	resource := bucketResource(bucket, attrs)
	for _, action := range [2]string{verbShare, verb} {
		if !s.authorize(w, r, claims, action, resource) {
			return
		}
	}
	expiresAt := time.Now().Add(ttl)
	payload := presign.Payload{
		Bucket:      bucket.Name,
		Key:         req.Key,
		Method:      req.Method,
		Subject:     claims.Subject,
		Kind:        claims.Kind,
		Team:        claims.Team,
		PermVer:     claims.PermVer,
		ExpiresAt:   expiresAt,
		ContentType: req.ContentType,
		MaxBytes:    s.presignMaxBytes(req.MaxBytes),
	}
	token, err := signer.Sign(payload)
	if err != nil {
		if errors.Is(err, presign.ErrMalformed) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
			return
		}
		s.Logger().Error("presign signing failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "", "service_unavailable")
		return
	}
	link, ok := s.presignURL(r, bucket.Name, req.Key, token)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "", "service_unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, presignMintResponse{
		URL:       link,
		Method:    payload.Method,
		Bucket:    bucket.Name,
		Key:       req.Key,
		ExpiresAt: time.Unix(expiresAt.Unix(), 0).UTC(),
	})
}

// presignTTL resolves the requested lifetime in seconds: zero selects the
// configured default, and a value above the configured maximum is rejected.
func (s *Server) presignTTL(seconds int64) (time.Duration, bool) {
	defaultTTL, maxTTL := config.DefaultPresignTTL, config.DefaultPresignMaxTTL
	if cfg := s.Config(); cfg != nil {
		if cfg.Presign.DefaultTTL > 0 {
			defaultTTL = cfg.Presign.DefaultTTL
		}
		if cfg.Presign.MaxTTL > 0 {
			maxTTL = cfg.Presign.MaxTTL
		}
	}
	if seconds == 0 {
		return defaultTTL, true
	}
	if seconds > int64(maxTTL/time.Second) {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// presignMaxBytes clamps an explicit upload cap to the configured object size
// limit. Zero asks for no token-level cap; the object limit still applies to
// the redemption because it is enforced by the upload path itself.
func (s *Server) presignMaxBytes(requested int64) int64 {
	if requested <= 0 {
		return 0
	}
	limit := int64(0)
	if cfg := s.Config(); cfg != nil {
		limit = cfg.Limits.ObjectMaxBytes
	}
	if limit <= 0 {
		limit = config.DefaultObjectMaxBytes
	}
	if requested > limit {
		return limit
	}
	return requested
}

// validPresignContentType reports whether the content type can be signed and
// later written back as an HTTP header: no control characters (a CR/LF would
// allow header injection) and a bounded length.
func validPresignContentType(contentType string) bool {
	if len(contentType) > maxPresignContentTypeBytes {
		return false
	}
	for i := 0; i < len(contentType); i++ {
		if char := contentType[i]; char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

// presignURL renders the absolute redemption URL for a token.
//
// With a configured PublicBaseURL the origin comes from configuration. Without
// one it is derived from the request, which makes the Host header (and so the
// link handed back to the caller) client controlled: only the scheme is taken
// from connection state, and no X-Forwarded-* header is trusted here because
// this path does not consult the trusted-proxy chain. Deployments behind a
// proxy that rewrites Host must set public_base_url.
func (s *Server) presignURL(r *http.Request, bucket, key, token string) (string, bool) {
	// EscapedPath percent-encodes every path segment while keeping the "/"
	// separators inside the object key.
	path := (&url.URL{Path: "/presign/" + bucket + "/" + key}).EscapedPath()
	query := "?sig=" + url.QueryEscape(token)
	if cfg := s.Config(); cfg != nil && cfg.PublicBaseURL != "" {
		return cfg.PublicBaseURL + path + query, true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if r.Host == "" {
		return "", false
	}
	return scheme + "://" + r.Host + path + query, true
}

// handlePresignRedeem serves GET/HEAD/PUT /presign/{bucket}/*?sig=.
//
// The check order is security relevant and deliberate: the signature is
// verified before anything touches the store, the bucket is resolved without
// revealing objects, and existence is only disclosed after the subject
// embedded in the signature is authorized against the *current* permissions
// (DecideSubject rejects a stale perm_ver), so a caller without a valid,
// currently-authorized signature learns nothing about buckets or keys.
func (s *Server) handlePresignRedeem(w http.ResponseWriter, r *http.Request) {
	signer := s.Signer()
	if signer == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("sig"))
	if token == "" {
		httpx.WriteProblem(w, r, http.StatusForbidden, "", "presign_invalid")
		return
	}
	bucketName, ok := decodedPathParam(r, "bucket")
	if !ok {
		httpx.WriteProblem(w, r, http.StatusForbidden, "", "presign_invalid")
		return
	}
	key, err := objectKeyFromPath(r)
	if err != nil || key == "" {
		httpx.WriteProblem(w, r, http.StatusForbidden, "", "presign_invalid")
		return
	}
	payload, err := signer.Verify(token, r.Method, bucketName, key, time.Now())
	switch {
	case err == nil:
	case errors.Is(err, presign.ErrExpired):
		httpx.WriteProblem(w, r, http.StatusGone, "", "presign_expired")
		return
	default:
		// A forged MAC, a token minted for another method/bucket/key and a
		// structurally broken token are answered identically, so probing cannot
		// distinguish "wrong object" from "forged".
		httpx.WriteProblem(w, r, http.StatusForbidden, "", "presign_invalid")
		return
	}
	if s.Store() == nil || s.Authorizer() == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	bucket, ok := s.bucketByName(w, r, payload.Bucket)
	if !ok {
		return
	}
	verb := verbRead
	attrs := map[string]any{"key": key}
	contentType := ""
	if payload.Method == http.MethodPut {
		verb = verbWrite
		// The payload's content type is authoritative because it is part of the
		// signature; the request header is only a fallback for tokens minted
		// without one.
		contentType = payload.ContentType
		if contentType == "" {
			contentType = strings.TrimSpace(r.Header.Get("Content-Type"))
		}
		if contentType == "" {
			contentType = defaultObjectContentType
		}
		attrs["content_type"] = contentType
		attrs["uploader"] = payload.Subject
		if r.ContentLength > 0 {
			attrs["size"] = r.ContentLength
		}
	}
	// The signature identified the subject; re-run the same cascade for that
	// subject so a permission or perm_ver change stops an outstanding URL.
	allowed, reason, err := s.Authorizer().DecideSubject(
		r.Context(), payload.Subject, payload.Kind, payload.Team, payload.PermVer, verb,
		bucketResource(bucket, attrs))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "iam_unavailable")
		return
	}
	if !allowed {
		s.deny(w, r, reason)
		return
	}
	if payload.Method == http.MethodPut {
		metadata, err := parseMetadataHeaders(r)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
			return
		}
		if payload.MaxBytes > 0 {
			// uploadObject reports *http.MaxBytesError as 413 payload_too_large,
			// so the token-level cap produces the same answer as the object cap.
			r.Body = http.MaxBytesReader(w, r.Body, payload.MaxBytes)
		}
		s.uploadObject(w, r, bucket, key, payload.Subject, contentType, metadata,
			strings.ToLower(strings.TrimSpace(r.Header.Get(headerSHA256))))
		return
	}
	object, err := s.Store().GetObject(r.Context(), bucket.ID, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "object_not_found")
			return
		}
		s.Logger().Error("presign object lookup failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	s.downloadObject(w, r, bucket, object)
}

// decodedPathParam returns a percent-decoded chi URL parameter. chi matches on
// RawPath, so captures stay encoded whenever the request used escapes; decode
// once here so handlers compare decoded values.
func decodedPathParam(r *http.Request, name string) (string, bool) {
	value := chi.URLParam(r, name)
	if value == "" {
		return "", false
	}
	if r.URL.RawPath == "" {
		return value, true
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", false
	}
	return decoded, true
}
