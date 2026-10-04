package httpapi

import (
	apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// docInitiateUploadRequest mirrors initiateUploadRequest for documentation:
// the optional fields carry omitempty so key is the only required property of
// the generated schema.
type docInitiateUploadRequest struct {
	Key         string            `json:"key"`
	ContentType string            `json:"content_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Size        *int64            `json:"size,omitempty"`
}

// docUploadOperations documents the multipart upload surface of a bucket.
var docUploadOperations = []apidocs.Operation{
	{
		Method:  "POST",
		Path:    "/api/v1/buckets/{bucket}/uploads",
		Tag:     "Uploads",
		Summary: "Initiate a multipart upload",
		Description: "Use to start a multipart upload for an object whose parts are uploaded separately and assembled at completion. " +
			"The bucket must exist and the caller needs the write grant on it; the decision runs before the upload row exists, against the prospective object context " +
			"(key, content type, uploader, and the declared size when supplied). The key follows the object key grammar (1-1024 bytes, no leading slash, no empty or dot segments, " +
			"no control characters) and metadata follows the object metadata rules (names up to 64 HTTP token characters, total name plus value up to 2048 bytes); a violation answers 400. " +
			"content_type defaults to application/octet-stream and the optional size must be >= 0 and is a declaration used only for the authorization attributes (-1 means unknown). " +
			"The JSON body is capped at 1 MiB. The returned upload_id expires after the configured upload TTL (24h by default), and part_count is 0 at creation. " +
			"Supply Idempotency-Key to retry safely: a replay returns the original 201 response, a concurrent duplicate answers 409, and the same key with a different body answers 422.",
		Security: "bearer",
		Request:  docInitiateUploadRequest{},
		RequestExample: map[string]any{
			"key":          "recordings/2026/10/03/lecture-04.mp4",
			"content_type": "video/mp4",
			"metadata":     map[string]string{"course": "cs-101", "source": "lecture-capture"},
			"size":         int64(3221225472),
		},
		Response: initiateUploadResponse{},
		ResponseExample: map[string]any{
			"upload_id":  "01J8ZQ5K2M4N6P8Q0R2S4T6V8W",
			"expires_at": "2026-10-05T09:15:00Z",
			"part_count": 0,
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_key", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docIdempotencyInProgress,
			docError(413, "payload_too_large", "Payload Too Large"),
			docIdempotencyConflict,
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:  "GET",
		Path:    "/api/v1/buckets/{bucket}/uploads/{uploadID}",
		Tag:     "Uploads",
		Summary: "Get a multipart upload",
		Description: "Use to inspect an in-progress multipart upload and the parts staged so far, for example before completing it or to resume after a client restart. " +
			"The upload must belong to the bucket in the path and must not have expired: an unknown or foreign upload id answers 404 upload_not_found and an expired one answers 410 upload_expired. " +
			"declared_size is the total declared at initiation (-1 when it was omitted) and part_count is the highest part number seen, not the number of staged parts. " +
			"parts lists the staged rows ordered by part number and is an empty array when nothing has been uploaded. Uploads are private to the subject that created them: " +
			"reading another subject's upload additionally requires the platform-wide filehouse:read:any grant.",
		PermissionNote: "Reading another subject's upload additionally requires the platform-wide filehouse:read:any grant.",
		Security:       "bearer",
		Response:       uploadDetailResponse{},
		ResponseExample: map[string]any{
			"upload_id":     "01J8ZQ5K2M4N6P8Q0R2S4T6V8W",
			"bucket_id":     "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
			"key":           "recordings/2026/10/03/lecture-04.mp4",
			"owner_id":      "01J8ZQ4F7G9K2M3N4P5Q6R7S8V",
			"content_type":  "video/mp4",
			"metadata":      map[string]string{"course": "cs-101", "source": "lecture-capture"},
			"declared_size": int64(3221225472),
			"part_count":    2,
			"created_at":    "2026-10-04T09:15:00Z",
			"expires_at":    "2026-10-05T09:15:00Z",
			"parts": []any{
				map[string]any{
					"upload_id":  "01J8ZQ5K2M4N6P8Q0R2S4T6V8W",
					"part_no":    1,
					"size":       int64(104857600),
					"sha256":     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
					"created_at": "2026-10-04T09:15:32Z",
				},
				map[string]any{
					"upload_id":  "01J8ZQ5K2M4N6P8Q0R2S4T6V8W",
					"part_no":    2,
					"size":       int64(52428800),
					"sha256":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					"created_at": "2026-10-04T09:16:05Z",
				},
			},
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "upload_not_found", "Not Found"),
			docError(410, "upload_expired", "Gone"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:  "PUT",
		Path:    "/api/v1/buckets/{bucket}/uploads/{uploadID}/parts/{partNo}",
		Tag:     "Uploads",
		Summary: "Upload a multipart upload part",
		Description: "Use to stage one part of a multipart upload before completing it. {partNo} must be an integer >= 1 (part numbers are stored as int32, so 2^31-1 is the practical maximum); " +
			"numbers need not be contiguous and re-uploading the same number replaces the staged part. The request body is the raw part bytes, not JSON. " +
			"The part size cap is the configured part limit (256 MiB by default, unlimited when disabled): a declared Content-Length over the cap is rejected immediately and streaming is bounded the same way, " +
			"both answering 413 payload_too_large. There is no minimum part size and zero-byte parts are accepted. Every part must arrive before the upload expires (24h TTL by default) or the answer is 410 upload_expired. " +
			"On success the staged part row is returned with its size and bare lowercase sha256, the digest that complete's optional per-part checks compare against. " +
			"Acting on another subject's upload additionally requires the platform-wide filehouse:write:any grant.",
		PermissionNote: "Acting on another subject's upload additionally requires the platform-wide filehouse:write:any grant.",
		Security:       "bearer",
		Request:        nil,
		Response:       store.UploadPart{},
		ResponseExample: map[string]any{
			"upload_id":  "01J8ZQ5K2M4N6P8Q0R2S4T6V8W",
			"part_no":    1,
			"size":       int64(104857600),
			"sha256":     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			"created_at": "2026-10-04T09:15:32Z",
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "upload_not_found", "Not Found"),
			docError(410, "upload_expired", "Gone"),
			docError(413, "payload_too_large", "Payload Too Large"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:  "POST",
		Path:    "/api/v1/buckets/{bucket}/uploads/{uploadID}/complete",
		Tag:     "Uploads",
		Summary: "Complete a multipart upload",
		Description: "Use to assemble the staged parts into one object and finish the multipart upload. The body lists the parts to assemble: every part_no must be >= 1 and the list must be strictly increasing, " +
			"but numbers need not be contiguous; the list must be non-empty and match the staged parts exactly in count and order, and a supplied sha256 is compared case-insensitively against the staged digest - " +
			"any violation answers 422 part_mismatch. The assembled bytes are committed through the same path as a direct PUT: the assembled size is re-authorized, an existing key is overwritten (still 201), " +
			"identical content deduplicates to one blob, and the bucket, owner, and team quotas are enforced transactionally, so a rejection answers 413 quota_exceeded without changing counters. " +
			"On success the full object is returned with ETag and X-Filehouse-SHA256 headers, and the upload row plus staged files are deleted, making the upload id unusable. " +
			"The JSON body is capped at 1 MiB; Idempotency-Key makes retries safe (409 while the original is in flight, 422 for a different body).",
		PermissionNote: "Acting on another subject's upload additionally requires the platform-wide filehouse:write:any grant.",
		Security:       "bearer",
		Request:        completeUploadRequest{},
		RequestExample: map[string]any{
			"parts": []any{
				map[string]any{"part_no": 1, "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
				map[string]any{"part_no": 2, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			},
		},
		Response: store.Object{},
		ResponseExample: map[string]any{
			"bucket_id":    "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
			"key":          "recordings/2026/10/03/lecture-04.mp4",
			"blob_hash":    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			"size":         int64(157286400),
			"etag":         "\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"",
			"content_type": "video/mp4",
			"owner_id":     "01J8ZQ4F7G9K2M3N4P5Q6R7S8V",
			"metadata":     map[string]string{"course": "cs-101", "source": "lecture-capture"},
			"created_at":   "2026-10-04T09:16:41Z",
			"updated_at":   "2026-10-04T09:16:41Z",
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "upload_not_found", "Not Found"),
			docIdempotencyInProgress,
			docError(410, "upload_expired", "Gone"),
			docError(413, "payload_too_large", "Payload Too Large"),
			docError(413, "quota_exceeded", "Payload Too Large"),
			docError(422, "part_mismatch", "Unprocessable Entity"),
			docIdempotencyConflict,
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:  "DELETE",
		Path:    "/api/v1/buckets/{bucket}/uploads/{uploadID}",
		Tag:     "Uploads",
		Summary: "Abort a multipart upload",
		Description: "Use to cancel an in-progress multipart upload and discard its staged parts. The upload must belong to the bucket in the path and must not have expired, " +
			"otherwise the answer is 404 upload_not_found or 410 upload_expired. The upload row is deleted first and then the staging directory; the upload id becomes permanently unusable, " +
			"no object is written, and no quota is affected. Aborting requires the write grant on the bucket, not delete, and acting on another subject's upload additionally requires the platform-wide filehouse:write:any grant. " +
			"The response has no body.",
		PermissionNote: "Aborting requires the write grant on the bucket; acting on another subject's upload additionally requires filehouse:write:any.",
		Security:       "bearer",
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "upload_not_found", "Not Found"),
			docError(410, "upload_expired", "Gone"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
}
