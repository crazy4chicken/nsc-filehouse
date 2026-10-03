package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	iam "github.com/crazy4chicken/nsc-teamusers/sdk/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/blob"
	"github.com/crazy4chicken/nsc-filehouse/internal/config"
	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

type initiateUploadRequest struct {
	Key         string            `json:"key"`
	ContentType string            `json:"content_type"`
	Metadata    map[string]string `json:"metadata"`
	// Size is the declared total object size; -1 (absent) means unknown.
	Size *int64 `json:"size"`
}

type initiateUploadResponse struct {
	UploadID  string    `json:"upload_id"`
	ExpiresAt time.Time `json:"expires_at"`
	PartCount int       `json:"part_count"`
}

type completeUploadPart struct {
	PartNo int    `json:"part_no"`
	SHA256 string `json:"sha256"`
}

type completeUploadRequest struct {
	Parts []completeUploadPart `json:"parts"`
}

type uploadDetailResponse struct {
	UploadID     string             `json:"upload_id"`
	BucketID     string             `json:"bucket_id"`
	Key          string             `json:"key"`
	OwnerID      string             `json:"owner_id"`
	ContentType  string             `json:"content_type"`
	Metadata     map[string]string  `json:"metadata"`
	DeclaredSize int64              `json:"declared_size"`
	PartCount    int                `json:"part_count"`
	CreatedAt    time.Time          `json:"created_at"`
	ExpiresAt    time.Time          `json:"expires_at"`
	Parts        []store.UploadPart `json:"parts"`
}

// handleInitiateUpload starts a multipart upload. The write decision runs
// before the row exists, against the prospective object context.
func (s *Server) handleInitiateUpload(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	var body initiateUploadRequest
	if !decodeRequestBody(w, r, &body) {
		return
	}
	if err := validateObjectKey(body.Key); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_key")
		return
	}
	if err := validateMetadata(body.Metadata); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return
	}
	contentType := strings.TrimSpace(body.ContentType)
	if contentType == "" {
		contentType = defaultObjectContentType
	}
	declaredSize := int64(-1)
	if body.Size != nil {
		if *body.Size < 0 {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
			return
		}
		declaredSize = *body.Size
	}
	attrs := map[string]any{"key": body.Key, "content_type": contentType, "uploader": claims.Subject}
	if declaredSize >= 0 {
		attrs["size"] = declaredSize
	}
	if !s.authorize(w, r, claims, verbWrite, bucketResource(bucket, attrs)) {
		return
	}
	ttl := s.limits().UploadTTL
	if ttl <= 0 {
		ttl = config.DefaultUploadTTL
	}
	upload, err := s.Store().CreateUpload(r.Context(), store.Upload{
		BucketID:     bucket.ID,
		Key:          body.Key,
		OwnerID:      claims.Subject,
		ContentType:  contentType,
		Metadata:     body.Metadata,
		DeclaredSize: declaredSize,
		ExpiresAt:    time.Now().Add(ttl),
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "bucket_not_found")
			return
		}
		s.log.Error("create upload failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	if err := s.Blobs().NewUpload(upload.ID); err != nil {
		// The row is left behind and expires into the reaper.
		s.log.Error("prepare upload staging failed", "error", err, "upload", upload.ID)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, initiateUploadResponse{
		UploadID:  upload.ID,
		ExpiresAt: upload.ExpiresAt,
		PartCount: upload.PartCount,
	})
}

// handleGetUpload returns the upload and its staged parts.
func (s *Server) handleGetUpload(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	upload, ok := s.uploadFor(w, r, bucket)
	if !ok {
		return
	}
	if !s.authorizeUpload(w, r, claims, verbRead, bucket, upload, nil) {
		return
	}
	parts, err := s.Store().ListUploadParts(r.Context(), upload.ID)
	if err != nil {
		s.log.Error("list upload parts failed", "error", err, "upload", upload.ID)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, uploadDetailResponse{
		UploadID:     upload.ID,
		BucketID:     upload.BucketID,
		Key:          upload.Key,
		OwnerID:      upload.OwnerID,
		ContentType:  upload.ContentType,
		Metadata:     upload.Metadata,
		DeclaredSize: upload.DeclaredSize,
		PartCount:    upload.PartCount,
		CreatedAt:    upload.CreatedAt,
		ExpiresAt:    upload.ExpiresAt,
		Parts:        parts,
	})
}

// handlePutUploadPart stages one part under the upload directory and records
// its size and digest.
func (s *Server) handlePutUploadPart(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	upload, ok := s.uploadFor(w, r, bucket)
	if !ok {
		return
	}
	partNo, ok := parsePartNo(w, r)
	if !ok {
		return
	}
	if !s.authorizeUpload(w, r, claims, verbWrite, bucket, upload, map[string]any{"part_no": int64(partNo)}) {
		return
	}
	maxBytes := s.limits().PartMaxBytes
	if maxBytes > 0 && r.ContentLength > maxBytes {
		httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "", "payload_too_large")
		return
	}
	size, sha, err := s.Blobs().PutPart(upload.ID, partNo, r.Body, maxBytes)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return
		case errors.Is(err, blob.ErrPartTooLarge):
			httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "", "payload_too_large")
			return
		}
		s.log.Error("stage upload part failed", "error", err, "upload", upload.ID, "part", partNo)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	part, err := s.Store().PutUploadPart(r.Context(), store.UploadPart{
		UploadID: upload.ID,
		PartNo:   partNo,
		Size:     size,
		SHA256:   sha,
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrUploadExpired):
			httpx.WriteProblem(w, r, http.StatusGone, "", "upload_expired")
		case errors.Is(err, store.ErrNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "upload_not_found")
		default:
			s.log.Error("record upload part failed", "error", err, "upload", upload.ID, "part", partNo)
			httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, part)
}

// handleAbortUpload cancels an upload: the row and the staged files are removed.
func (s *Server) handleAbortUpload(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	upload, ok := s.uploadFor(w, r, bucket)
	if !ok {
		return
	}
	if !s.authorizeUpload(w, r, claims, verbWrite, bucket, upload, nil) {
		return
	}
	if err := s.Store().DeleteUpload(r.Context(), upload.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "upload_not_found")
			return
		}
		s.log.Error("delete upload failed", "error", err, "upload", upload.ID)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	if err := s.Blobs().DropUpload(upload.ID); err != nil {
		// The row is gone, so the staging directory is unreachable; the reaper
		// removes leftovers.
		s.log.Warn("drop upload staging failed", "error", err, "upload", upload.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCompleteUpload validates the client part list against the staged parts,
// assembles the object and commits it through the same quota enforcing path as
// a direct PUT.
func (s *Server) handleCompleteUpload(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.claimsFor(w, r)
	if !ok {
		return
	}
	bucket, ok := s.bucketFor(w, r)
	if !ok {
		return
	}
	upload, ok := s.uploadFor(w, r, bucket)
	if !ok {
		return
	}
	var body completeUploadRequest
	if !decodeRequestBody(w, r, &body) {
		return
	}
	for i, part := range body.Parts {
		if part.PartNo < 1 || (i > 0 && part.PartNo <= body.Parts[i-1].PartNo) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
			return
		}
	}
	stored, err := s.Store().ListUploadParts(r.Context(), upload.ID)
	if err != nil {
		s.log.Error("list upload parts failed", "error", err, "upload", upload.ID)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	if len(body.Parts) == 0 || len(body.Parts) != len(stored) {
		httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "", "part_mismatch")
		return
	}
	numbers := make([]int, 0, len(stored))
	var total int64
	for i, part := range body.Parts {
		if part.PartNo != stored[i].PartNo {
			httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "", "part_mismatch")
			return
		}
		if sha := strings.TrimSpace(part.SHA256); sha != "" && !strings.EqualFold(sha, stored[i].SHA256) {
			httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "", "part_mismatch")
			return
		}
		numbers = append(numbers, part.PartNo)
		total += stored[i].Size
	}
	if !s.authorizeUpload(w, r, claims, verbWrite, bucket, upload, map[string]any{"size": total}) {
		return
	}
	hash, size, _, err := s.Blobs().AssembleUpload(r.Context(), upload.ID, numbers)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return
		case errors.Is(err, blob.ErrUploadIncomplete):
			httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "", "part_mismatch")
			return
		}
		s.log.Error("assemble upload failed", "error", err, "upload", upload.ID)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return
	}
	object, ok := s.commitBlob(w, r, bucket, upload.Key, upload.OwnerID, upload.ContentType, upload.Metadata, hash, size)
	if !ok {
		s.releaseUncommittedBlob(r.Context(), hash)
		return
	}
	if err := s.Store().DeleteUpload(r.Context(), upload.ID); err != nil {
		s.log.Warn("delete completed upload failed", "error", err, "upload", upload.ID)
	}
	if err := s.Blobs().DropUpload(upload.ID); err != nil {
		s.log.Warn("drop completed upload staging failed", "error", err, "upload", upload.ID)
	}
	w.Header().Set("ETag", object.ETag)
	w.Header().Set(headerSHA256, object.BlobHash)
	httpx.WriteJSON(w, http.StatusCreated, object)
}

// uploadFor loads the {uploadID} of the bucket, verifying that it belongs to
// the bucket and has not expired. It writes its own errors.
func (s *Server) uploadFor(w http.ResponseWriter, r *http.Request, bucket store.Bucket) (store.Upload, bool) {
	upload, err := s.Store().GetUpload(r.Context(), chi.URLParam(r, "uploadID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "", "upload_not_found")
			return store.Upload{}, false
		}
		s.log.Error("load upload failed", "error", err)
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "", "service_unavailable")
		return store.Upload{}, false
	}
	if upload.BucketID != bucket.ID {
		httpx.WriteProblem(w, r, http.StatusNotFound, "", "upload_not_found")
		return store.Upload{}, false
	}
	if time.Now().After(upload.ExpiresAt) {
		httpx.WriteProblem(w, r, http.StatusGone, "", "upload_expired")
		return store.Upload{}, false
	}
	return upload, true
}

// authorizeUpload gates an operation on a multipart upload: the bucket level
// decision first, plus the platform wide (":any") grant when the upload belongs
// to another subject. An upload is private to its owner, so acting on somebody
// else's upload always needs the broadest scope.
func (s *Server) authorizeUpload(w http.ResponseWriter, r *http.Request, claims iam.Claims, verb string, bucket store.Bucket, upload store.Upload, extra map[string]any) bool {
	attrs := make(map[string]any, len(extra)+2)
	for name, value := range extra {
		attrs[name] = value
	}
	attrs["key"] = upload.Key
	attrs["uploader"] = upload.OwnerID
	if upload.ContentType != "" {
		attrs["content_type"] = upload.ContentType
	}
	if !s.authorize(w, r, claims, verb, bucketResource(bucket, attrs)) {
		return false
	}
	if upload.OwnerID == claims.Subject {
		return true
	}
	// Empty resource: the cascade only attempts the ":any" scope key.
	return s.decideAny(w, r, claims, verb)
}

// parsePartNo reads the {partNo} route parameter.
func parsePartNo(w http.ResponseWriter, r *http.Request) (int, bool) {
	partNo, err := strconv.Atoi(chi.URLParam(r, "partNo"))
	if err != nil || partNo < 1 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "", "invalid_request")
		return 0, false
	}
	return partNo, true
}
