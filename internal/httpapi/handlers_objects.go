package httpapi

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/crazy4chicken/nsc-filehouse/internal/blob"
	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

const (
	// maxObjectKeyBytes is the contract object key bound (§5).
	maxObjectKeyBytes = 1024
	// metadataHeaderPrefix carries object metadata on writes and reads.
	metadataHeaderPrefix = "X-Filehouse-Meta-"
	// maxMetadataBytes is the contract metadata bound (§5).
	maxMetadataBytes = 2 << 10
	// defaultObjectContentType is stored when a request supplies none.
	defaultObjectContentType = "application/octet-stream"
	// headerSHA256 carries the object digest: the bare lowercase sha256 hex on
	// the wire, while the stored ETag is the quoted form.
	headerSHA256 = "X-Filehouse-SHA256"
)

// objectPage is the paginated object listing envelope.
type objectPage struct {
	Items      []store.Object `json:"items"`
	NextCursor string         `json:"next_cursor"`
}

// validateObjectKey enforces the contract object key grammar (§5): 1–1024
// bytes, no leading slash, no empty or dot segments, no control characters.
func validateObjectKey(key string) error {
	if key == "" {
		return errors.New("object key is empty")
	}
	if len(key) > maxObjectKeyBytes {
		return fmt.Errorf("object key exceeds %d bytes", maxObjectKeyBytes)
	}
	if strings.HasPrefix(key, "/") {
		return errors.New("object key must not start with a slash")
	}
	if strings.Contains(key, "//") {
		return errors.New("object key must not contain an empty segment")
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "." || segment == ".." {
			return errors.New("object key must not contain dot segments")
		}
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] == 0x7f {
			return errors.New("object key must not contain control characters")
		}
	}
	return nil
}

// objectKeyFromPath returns the object key captured by the trailing wildcard
// route. chi v5 has no "{key...}" catch-all, so the route ends in "*" and the
// wildcard value is the remainder of the path without its leading slash; an
// empty remainder (a bare "/objects/") stays empty and fails validation. chi
// matches the raw (still escaped) path when the URL carries escapes, so that
// form is decoded exactly once here.
func objectKeyFromPath(r *http.Request) (string, error) {
	key := chi.URLParam(r, "*")
	if r.URL.RawPath != "" {
		decoded, err := url.PathUnescape(key)
		if err != nil {
			return "", err
		}
		key = decoded
	}
	return key, nil
}

// validMetadataName reports whether name is a usable metadata key. Request
// header names arrive canonicalised, so the accepted alphabet is the HTTP
// token set.
func validMetadataName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		char := name[i]
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		case char == '!', char == '#', char == '$', char == '%', char == '&', char == '\'',
			char == '*', char == '+', char == '-', char == '.', char == '^', char == '_',
			char == '`', char == '|', char == '~':
		default:
			return false
		}
	}
	return true
}

func validMetadataValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

// validateMetadata enforces the metadata bounds of the contract: safe keys and
// values, and at most 2 KiB in total.
func validateMetadata(metadata map[string]string) error {
	total := 0
	for name, value := range metadata {
		if !validMetadataName(name) {
			return fmt.Errorf("invalid metadata name %q", name)
		}
		if !validMetadataValue(value) {
			return fmt.Errorf("invalid metadata value for %q", name)
		}
		total += len(name) + len(value)
	}
	if total > maxMetadataBytes {
		return fmt.Errorf("metadata exceeds %d bytes", maxMetadataBytes)
	}
	return nil
}

// parseMetadataHeaders collects the X-Filehouse-Meta-* request headers. Go
// canonicalises header names, so the metadata key is the canonical suffix, the
// only spelling the server can observe, and it round-trips through reads.
func parseMetadataHeaders(r *http.Request) (map[string]string, error) {
	var metadata map[string]string
	for name, values := range r.Header {
		if len(name) <= len(metadataHeaderPrefix) || !strings.EqualFold(name[:len(metadataHeaderPrefix)], metadataHeaderPrefix) {
			continue
		}
		key := name[len(metadataHeaderPrefix):]
		if metadata == nil {
			metadata = make(map[string]string, len(values))
		}
		for _, value := range values {
			metadata[key] = value
		}
	}
	if err := validateMetadata(metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

// handleListObjects lists one page of a bucket ordered by key.
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	if !s.authorize(w, r, claims, verbRead, bucketResource(bucket, nil)) {
		return
	}
	limit, ok := parsePageLimit(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	items, next, err := s.Store().ListObjects(r.Context(), bucket.ID, query.Get("prefix"), query.Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, store.ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
			return
		}
		s.log.Error("list objects failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, objectPage{Items: items, NextCursor: next})
}

// handlePutObject streams the request body into the blob store and commits the
// object. The write decision runs before the body is read with every attribute
// known up front, including the declared Content-Length so size conditions can
// apply; the store still enforces the quotas atomically.
func (s *Server) handlePutObject(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	key, err := objectKeyFromPath(r)
	if err != nil || validateObjectKey(key) != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_key")
		return
	}
	metadata, err := parseMetadataHeaders(r)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = defaultObjectContentType
	}
	attrs := map[string]any{"key": key, "content_type": contentType, "uploader": claims.Subject}
	if r.ContentLength > 0 {
		attrs["size"] = r.ContentLength
	}
	if !s.authorize(w, r, claims, verbWrite, bucketResource(bucket, attrs)) {
		return
	}
	expectedSHA := strings.ToLower(strings.TrimSpace(r.Header.Get(headerSHA256)))
	s.uploadObject(w, r, bucket, key, claims.Subject, contentType, metadata, expectedSHA)
}

// handleGetObject serves both GET and HEAD: http.ServeContent answers the HEAD
// variant with headers only and implements Range and conditional requests.
func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	key, err := objectKeyFromPath(r)
	if err != nil || validateObjectKey(key) != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_key")
		return
	}
	if !s.authorize(w, r, claims, verbRead, bucketResource(bucket, map[string]any{"key": key})) {
		return
	}
	object, err := s.Store().GetObject(r.Context(), bucket.ID, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "object_not_found")
			return
		}
		s.log.Error("load object failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	s.downloadObject(w, r, bucket, object)
}

// handleDeleteObject removes one object. The blob file is left to the reaper:
// the refcount drop is transactional, and removing the file here could race a
// concurrent upload that just deduplicated against it.
func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	key, err := objectKeyFromPath(r)
	if err != nil || validateObjectKey(key) != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_key")
		return
	}
	if !s.authorize(w, r, claims, verbDelete, bucketResource(bucket, map[string]any{"key": key})) {
		return
	}
	_, err = s.Store().DeleteObject(r.Context(), bucket.ID, key)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "", "object_not_found")
	default:
		s.log.Error("delete object failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
	}
}

// downloadObject serves an object body with Range and conditional request
// support. It performs no authorization of its own: the caller decides first.
func (s *Server) downloadObject(w http.ResponseWriter, r *http.Request, bucket store.Bucket, object store.Object) {
	file, err := s.Blobs().Open(object.BlobHash)
	if err != nil {
		s.log.Error("open blob failed", "error", err, "bucket", bucket.Name, "key", object.Key, "hash", object.BlobHash)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	defer file.Close()
	header := w.Header()
	header.Set("ETag", object.ETag)
	header.Set(headerSHA256, object.BlobHash)
	contentType := object.ContentType
	if contentType == "" {
		contentType = defaultObjectContentType
	}
	header.Set("Content-Type", contentType)
	for name, value := range object.Metadata {
		header.Set(metadataHeaderPrefix+name, value)
	}
	name := path.Base(object.Key)
	if r.URL.Query().Get("download") == "1" {
		header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	}
	http.ServeContent(w, r, name, object.UpdatedAt, file)
}

// uploadObject streams the request body into the content addressed blob store,
// verifies a client supplied digest, enforces the configured object size bound
// and commits the object through the quota enforcing store path. It performs no
// authorization of its own: the caller decides first. It writes its own errors
// and its own 201 response, so the presigned PUT shares one code path.
func (s *Server) uploadObject(w http.ResponseWriter, r *http.Request, bucket store.Bucket, key, ownerID, contentType string, metadata map[string]string, expectedSHA string) {
	if err := validateMetadata(metadata); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	if contentType == "" {
		contentType = defaultObjectContentType
	}
	maxBytes := s.limits().ObjectMaxBytes
	if maxBytes > 0 {
		if r.ContentLength > maxBytes {
			httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "", "payload_too_large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	hash, size, _, err := s.Blobs().PutVerified(r.Context(), r.Body, expectedSHA)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			// The client went away; there is nobody left to answer.
			return
		case errors.Is(err, blob.ErrChecksumMismatch):
			httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "", "checksum_mismatch")
			return
		}
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "", "payload_too_large")
			return
		}
		s.log.Error("store blob failed", "error", err, "bucket", bucket.Name, "key", key)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	object, ok := s.commitBlob(w, r, bucket, key, ownerID, contentType, metadata, hash, size)
	if !ok {
		s.releaseUncommittedBlob(r.Context(), hash)
		return
	}
	w.Header().Set("ETag", object.ETag)
	w.Header().Set(headerSHA256, object.BlobHash)
	httpx.WriteJSON(w, http.StatusCreated, object)
}

// commitBlob writes the object metadata for an already stored blob, enforcing
// the owner and team quotas atomically with the write. It writes its own errors
// and returns ok = false when the response is already sent. A rejected commit
// leaves the blob behind with a zero refcount: callers pass the hash to
// releaseUncommittedBlob, and the reaper's orphan sweep is the backstop.
func (s *Server) commitBlob(w http.ResponseWriter, r *http.Request, bucket store.Bucket, key, ownerID, contentType string, metadata map[string]string, hash string, size int64) (store.Object, bool) {
	ctx := r.Context()
	ownerQuota, err := s.quotaLimit(ctx, "user", ownerID)
	if err != nil {
		s.log.Error("load owner quota failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return store.Object{}, false
	}
	var teamQuota store.QuotaLimit
	if bucket.TeamID != "" {
		if teamQuota, err = s.quotaLimit(ctx, "team", bucket.TeamID); err != nil {
			s.log.Error("load team quota failed", "error", err)
			httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
			return store.Object{}, false
		}
	}
	object, err := s.Store().PutObject(ctx, store.PutObjectRequest{
		BucketID:    bucket.ID,
		Key:         key,
		BlobHash:    hash,
		Size:        size,
		ContentType: contentType,
		OwnerID:     ownerID,
		Metadata:    metadata,
		Replace:     true,
		OwnerQuota:  ownerQuota,
		TeamQuota:   teamQuota,
	})
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return store.Object{}, false
		case errors.Is(err, store.ErrQuotaExceeded):
			httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "", "quota_exceeded")
			return store.Object{}, false
		case errors.Is(err, store.ErrNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "bucket_not_found")
			return store.Object{}, false
		}
		s.log.Error("put object failed", "error", err, "bucket", bucket.Name, "key", key)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return store.Object{}, false
	}
	return object, true
}

// releaseUncommittedBlob cleans up content that was written to the blob store
// but whose object commit failed, e.g. a quota rejection. The guarded row
// delete only proceeds while the blob is still unreferenced, so a live object
// that deduplicates against the file is never disturbed; when it declines, the
// file is left for the reaper's orphan sweep. Cleanup is best effort and only
// logged at debug level: the response to the client is already decided.
func (s *Server) releaseUncommittedBlob(ctx context.Context, hash string) {
	deleted, err := s.Store().DeleteBlob(ctx, hash, 0)
	if err != nil {
		s.log.Debug("cleanup uncommitted blob: delete row failed", "error", err, "hash", hash)
		return
	}
	if !deleted {
		return
	}
	if err := s.Blobs().Remove(hash); err != nil && !errors.Is(err, blob.ErrNotFound) {
		s.log.Debug("cleanup uncommitted blob: remove file failed", "error", err, "hash", hash)
	}
}

// quotaLimit resolves the aggregate quota of a subject; a missing row means
// unlimited.
func (s *Server) quotaLimit(ctx context.Context, kind, id string) (store.QuotaLimit, error) {
	if id == "" {
		return store.QuotaLimit{}, nil
	}
	quota, found, err := s.Store().GetQuota(ctx, kind, id)
	if err != nil {
		return store.QuotaLimit{}, err
	}
	if !found {
		return store.QuotaLimit{}, nil
	}
	return store.QuotaLimit{MaxBytes: quota.MaxBytes, MaxObjects: quota.MaxObjects}, nil
}
