package httpapi

import (
	apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// docCreateBucketRequest mirrors createBucketRequest for schema generation. The
// handler treats every field except name as optional, but the real struct tags
// carry no omitempty, so the doc mirror restates the optionality the emitter
// reads from the tags.
type docCreateBucketRequest struct {
	Name         string `json:"name"`
	TeamID       string `json:"team_id,omitempty"`
	Description  string `json:"description,omitempty"`
	QuotaBytes   *int64 `json:"quota_bytes,omitempty"`
	QuotaObjects *int64 `json:"quota_objects,omitempty"`
}

// docPatchBucketRequest mirrors patchBucketRequest: every field is optional and
// at least one must be present.
type docPatchBucketRequest struct {
	Description  *string `json:"description,omitempty"`
	QuotaBytes   *int64  `json:"quota_bytes,omitempty"`
	QuotaObjects *int64  `json:"quota_objects,omitempty"`
}

// docBucketExample returns one production-shaped bucket payload; every bucket
// route answers with the same representation.
func docBucketExample() map[string]any {
	return map[string]any{
		"id":            "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
		"name":          "media-assets",
		"owner_id":      "01J8ZQ4F7G9K2M3N4P5Q6R7S9A",
		"owner_kind":    "user",
		"team_id":       "",
		"description":   "Media assets for the documentation site",
		"quota_bytes":   int64(107374182400),
		"quota_objects": int64(10000),
		"used_bytes":    int64(52428800),
		"used_objects":  int64(128),
		"created_at":    "2026-09-30T08:12:34Z",
		"updated_at":    "2026-10-04T09:15:00Z",
	}
}

// docBucketPageExample returns a one-item bucket page with a continuation
// cursor for the listing example.
func docBucketPageExample() map[string]any {
	return map[string]any{
		"items":       []any{docBucketExample()},
		"next_cursor": "eyJ2IjoxLCJzIjoiYnVja2V0c3wwMUo4WlE0RjdHOUsyTTNONFA1UTZSN1M5QXx1c2VyfHwiLCJjIjoibWVkaWEtYXNzZXRzIn0",
	}
}

// docBucketOperations is the route contract of the bucket surface: listing and
// creation on the collection plus read, update and delete by name.
var docBucketOperations = []apidocs.Operation{
	{
		Method:          "GET",
		Path:            "/api/v1/buckets",
		Tag:             "Buckets",
		Summary:         "List buckets",
		Description:     "Use to list the buckets the caller may read, ordered by name ascending. Supports the optional ?limit= (default 100, values above 1000 are clamped) and ?cursor= query parameters: next_cursor is an opaque token that is only valid for the same caller grant mode and filter scope, and a malformed, foreign or stale cursor is 400 invalid_request. The candidate set is derived from the caller's effective grants and every candidate is re-verified by an authorization decision, so a bucket the cascade denies is dropped from the page (fail-closed) and a decision failure is 503 iam_unavailable. items is [] when the page is empty and an empty next_cursor marks the last page.",
		Security:        "bearer",
		Response:        bucketPage{},
		ResponseExample: docBucketPageExample(),
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:      "POST",
		Path:        "/api/v1/buckets",
		Tag:         "Buckets",
		Summary:     "Create a bucket",
		Description: "Use to create a bucket owned by the caller. name must match ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ (3-63 characters: lowercase letters, digits, dot and hyphen, starting and ending with an alphanumeric) and is unique; a duplicate name is 409 bucket_exists. team_id attaches the bucket to a team and is empty for a personal bucket. quota_bytes and quota_objects default to the configured bucket defaults and 0 means unlimited; negative values are 400 invalid_request. Write permission is decided against the prospective bucket (owner = caller, team = team_id) before insertion, and success is 201 with the full bucket row. The JSON body is limited to 1 MiB. Accepts Idempotency-Key: a replay of a completed request returns the original 201 response with Idempotency-Replayed: true, a concurrent request with the same key is 409 idempotency_in_progress, and reusing the key with a different body is 422 idempotency_conflict.",
		Security:    "bearer",
		Request:     docCreateBucketRequest{},
		RequestExample: map[string]any{
			"name":          "media-assets",
			"description":   "Media assets for the documentation site",
			"quota_bytes":   int64(107374182400),
			"quota_objects": int64(10000),
		},
		Response:        store.Bucket{},
		ResponseExample: docBucketExample(),
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(409, "bucket_exists", "Conflict"),
			docIdempotencyInProgress,
			docError(413, "payload_too_large", "Payload Too Large"),
			docIdempotencyConflict,
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:          "GET",
		Path:            "/api/v1/buckets/{bucket}",
		Tag:             "Buckets",
		Summary:         "Get a bucket",
		Description:     "Use to read one bucket's attributes and counters by its unique name. The response carries the bucket's quotas (0 means unlimited) and its live used_bytes/used_objects counters, which move transactionally with object writes. Requires read permission on the bucket; a name outside the bucket grammar is 400 invalid_bucket_name and an unknown name is 404 bucket_not_found.",
		Security:        "bearer",
		Response:        store.Bucket{},
		ResponseExample: docBucketExample(),
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:         "PATCH",
		Path:           "/api/v1/buckets/{bucket}",
		Tag:            "Buckets",
		Summary:        "Update a bucket",
		Description:    "Use to update a bucket's mutable attributes. The JSON body (limited to 1 MiB) must carry at least one of description, quota_bytes or quota_objects; an empty body or a negative quota is 400 invalid_request. Write permission on the bucket is required for every change, and setting quota_bytes or quota_objects additionally requires the platform-wide filehouse:manage:any grant because a quota bounds every future writer of the bucket. A quota of 0 means unlimited. The updated bucket is returned; an unknown name is 404 bucket_not_found.",
		PermissionNote: "Setting quota_bytes or quota_objects additionally requires the platform-wide filehouse:manage:any grant.",
		Security:       "bearer",
		Request:        docPatchBucketRequest{},
		RequestExample: map[string]any{
			"description": "Media assets for the documentation site",
			"quota_bytes": int64(214748364800),
		},
		Response:        store.Bucket{},
		ResponseExample: docBucketExample(),
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(413, "payload_too_large", "Payload Too Large"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:      "DELETE",
		Path:        "/api/v1/buckets/{bucket}",
		Tag:         "Buckets",
		Summary:     "Delete a bucket",
		Description: "Use to delete an empty bucket. The bucket must hold no object rows; a non-empty bucket is 409 bucket_not_empty and nothing is removed. Requires delete permission on the bucket. A name outside the bucket grammar is 400 invalid_bucket_name and an unknown name is 404 bucket_not_found. Success is 204 with no body, and deleting the same bucket twice is 404 on the second call.",
		Security:    "bearer",
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(409, "bucket_not_empty", "Conflict"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
}
