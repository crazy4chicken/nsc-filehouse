package httpapi

import (
	apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/gc"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// docAdminStatsResponse is the flat documentation mirror of
// adminStatsResponse. The schema reflector does not inline embedded structs,
// so the store.Stats totals are spelled out here field for field with the JSON
// names and types the endpoint emits.
type docAdminStatsResponse struct {
	Buckets        int64 `json:"buckets"`
	Objects        int64 `json:"objects"`
	LogicalBytes   int64 `json:"logical_bytes"`
	Blobs          int64 `json:"blobs"`
	BlobBytes      int64 `json:"blob_bytes"`
	ZeroRefBlobs   int64 `json:"zero_ref_blobs"`
	Uploads        int64 `json:"uploads"`
	ExpiredUploads int64 `json:"expired_uploads"`
	Quotas         int64 `json:"quotas"`
	PhysicalBlobs  int64 `json:"physical_blobs"`
	PhysicalBytes  int64 `json:"physical_bytes"`
}

// docAdminOperations documents the management plane. Every route requires the
// any-scoped manage grant and runs the decision against an empty resource, so
// team- and own-scoped grants never satisfy it.
var docAdminOperations = []apidocs.Operation{
	{
		Method:      "GET",
		Path:        "/api/v1/admin/stats",
		Tag:         "Admin",
		Summary:     "Get platform statistics",
		Description: "Use to monitor the platform and to reconcile the metadata totals against the blob directory. Requires filehouse:manage:any. The response carries the store totals (buckets, object rows, logical bytes, blobs, blob bytes, zero-refcount blobs, live and expired uploads, quota rows) plus physical_blobs and physical_bytes measured by walking the blob directory. The walk is bounded at 1,000,000 files so a huge or damaged directory cannot stall the request, and files that disappear mid-walk (a concurrent GC pass) are skipped; the physical figures are a point-in-time approximation. Answers 503 when the metadata store or the blob directory is unavailable.",
		Security:    "bearer",
		Response:    docAdminStatsResponse{},
		ResponseExample: map[string]any{
			"buckets":         64,
			"objects":         12043,
			"logical_bytes":   34359738368,
			"blobs":           10978,
			"blob_bytes":      31534882816,
			"zero_ref_blobs":  12,
			"uploads":         4,
			"expired_uploads": 1,
			"quotas":          37,
			"physical_blobs":  10990,
			"physical_bytes":  31534918656,
		},
		Errors: []apidocs.ErrorDoc{
			docUnauthorized,
			docForbidden,
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:      "GET",
		Path:        "/api/v1/admin/quotas",
		Tag:         "Admin",
		Summary:     "List quota overrides",
		Description: "Use to review the per-subject quota overrides. Requires filehouse:manage:any. An absent or empty kind lists user and team quotas together, ordered by (subject_kind, subject_id); a non-empty kind must be user or team. Pagination uses limit (default 100, maximum 1000) and the opaque cursor, which is scoped to the selected kind - changing kind between pages answers 400 invalid_request. items is [] when nothing matches and next_cursor is empty on the last page. A zero max_bytes or max_objects leaves that dimension unlimited.",
		Security:    "bearer",
		Response:    quotaListResponse{},
		ResponseExample: map[string]any{
			"items": []any{
				map[string]any{
					"subject_kind": "user",
					"subject_id":   "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
					"max_bytes":    10737418240,
					"max_objects":  250000,
					"updated_at":   "2026-03-14T09:30:00Z",
				},
				map[string]any{
					"subject_kind": "team",
					"subject_id":   "01J8ZP2Q4R6S8T0V2W4X6Y8ZB",
					"max_bytes":    0,
					"max_objects":  0,
					"updated_at":   "2026-02-02T18:05:41Z",
				},
			},
			"next_cursor": "",
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:      "PUT",
		Path:        "/api/v1/admin/quotas/{kind}/{id}",
		Tag:         "Admin",
		Summary:     "Upsert a quota override",
		Description: "Use to set or clear the storage quota of one subject. Requires filehouse:manage:any. kind must be user or team and id is the subject identifier (trimmed, 1-256 bytes); both path segments are percent-decoded once. The JSON body carries max_bytes and max_objects: an omitted or zero field leaves that dimension unlimited, a negative value answers 400 invalid_request, and a body larger than 1 MiB answers 413 payload_too_large. The row is upserted and read back, so the response is the stored quota row - including updated_at - rather than an echo of the request; a read-back inconsistency answers 503 service_unavailable.",
		Security:    "bearer",
		Request:     adminQuotaRequest{},
		RequestExample: map[string]any{
			"max_bytes":   10737418240,
			"max_objects": 250000,
		},
		Response: store.Quota{},
		ResponseExample: map[string]any{
			"subject_kind": "user",
			"subject_id":   "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
			"max_bytes":    10737418240,
			"max_objects":  250000,
			"updated_at":   "2026-03-14T09:30:00Z",
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(413, "payload_too_large", "Payload Too Large"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:      "POST",
		Path:        "/api/v1/admin/gc",
		Tag:         "Admin",
		Summary:     "Run a garbage collection pass",
		Description: "Use to reclaim storage on demand. Requires filehouse:manage:any and runs one complete reaper pass synchronously: unreferenced blobs past the GC grace period, expired multipart uploads, idempotency records older than the 24-hour retention, and orphan blob files are deleted. The response is the pass report; a pass that hits per-step failures still answers 200 with a non-zero errors counter, because every reachable step has already completed and the details only exist in the server log. Send an Idempotency-Key to make retries safe: a replay returns the original report, a duplicate while the pass is still running answers 409 idempotency_in_progress, and reusing the key with a different body answers 422 idempotency_conflict. Answers 503 service_unavailable when no reaper is configured or the metadata store is unreachable.",
		Security:    "bearer",
		Response:    gc.Report{},
		ResponseExample: map[string]any{
			"blobs_deleted":        128,
			"bytes_deleted":        9663676416,
			"uploads_deleted":      3,
			"idempotency_deleted":  57,
			"orphan_files_deleted": 2,
			"orphan_bytes_deleted": 1048576,
			"errors":               0,
		},
		Errors: []apidocs.ErrorDoc{
			docUnauthorized,
			docForbidden,
			docIdempotencyInProgress,
			docIdempotencyConflict,
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
}
