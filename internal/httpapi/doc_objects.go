package httpapi

import (
	apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// docObjectExample returns one production-shaped object payload; object reads
// and writes answer with the same representation.
func docObjectExample() map[string]any {
	return map[string]any{
		"bucket_id":    "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
		"key":          "reports/2026/q3-summary.pdf",
		"blob_hash":    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"size":         int64(2411724),
		"etag":         "\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"",
		"content_type": "application/pdf",
		"owner_id":     "01J8ZQ4F7G9K2M3N4P5Q6R7S9A",
		"metadata":     map[string]any{"Origin": "nightly-export", "Retention-Days": "90"},
		"created_at":   "2026-10-01T21:03:11Z",
		"updated_at":   "2026-10-01T21:03:11Z",
	}
}

// docObjectPageExample returns a one-item object page with a continuation
// cursor for the listing example.
func docObjectPageExample() map[string]any {
	return map[string]any{
		"items":       []any{docObjectExample()},
		"next_cursor": "eyJ2IjoxLCJzIjoib2JqZWN0c3wwMUo4WlE0RjdHOUsyTTNONFA1UTZSN1M4VHxyZXBvcnRzLyIsImMiOiJyZXBvcnRzLzIwMjYvcTMtc3VtbWFyeS5wZGYifQ",
	}
}

// docObjectOperations is the route contract of the object surface: listing plus
// byte upload, download, metadata read and delete on the trailing wildcard key.
var docObjectOperations = []apidocs.Operation{
	{
		Method:          "GET",
		Path:            "/api/v1/buckets/{bucket}/objects",
		Tag:             "Objects",
		Summary:         "List objects",
		Description:     "Use to list one page of a bucket's objects ordered by key ascending. Supports the optional ?prefix= (only keys starting with the given string), ?limit= (default 100, values above 1000 are clamped) and ?cursor= query parameters: next_cursor is an opaque token bound to the bucket and prefix, so changing the prefix between pages or presenting a malformed or foreign cursor is 400 invalid_request. items is [] when the page is empty and an empty next_cursor marks the last page. Requires read permission on the bucket; an unknown bucket is 404 bucket_not_found.",
		Security:        "bearer",
		Response:        objectPage{},
		ResponseExample: docObjectPageExample(),
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:          "PUT",
		Path:            "/api/v1/buckets/{bucket}/objects/*",
		Tag:             "Objects",
		Summary:         "Upload an object",
		Description:     "Use to upload or replace one object's bytes. The request body is the raw object content, not JSON, and the key is the trailing wildcard path segment, percent-decoded once: keys are 1-1024 bytes and must not start with a slash, contain empty or dot segments, or control characters, otherwise 400 invalid_key. Content-Type is stored as sent and defaults to application/octet-stream. X-Filehouse-SHA256 optionally carries the expected 64-character hex SHA-256; a malformed value or a digest mismatch is 422 checksum_mismatch. `X-Filehouse-Meta-<Name>` headers attach metadata (name of at most 64 HTTP token characters, name and value at most 2048 bytes in total) and are echoed on reads. The body is capped by the configured object maximum (5 GiB by default): a declared Content-Length above the cap is rejected immediately and the stream is enforced while reading, both 413 payload_too_large. The write always replaces an existing key and answers 201 with the stored object plus ETag (quoted SHA-256) and X-Filehouse-SHA256 headers; identical content is deduplicated by SHA-256 and shares one blob. Bucket, owner and team quotas are enforced transactionally at commit; a rejection is 413 quota_exceeded and leaves counters and refcounts unchanged. Requires write permission on the bucket, decided before the body is read.",
		Security:        "bearer",
		Response:        store.Object{},
		ResponseExample: docObjectExample(),
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_key", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(413, "payload_too_large", "Payload Too Large"),
			docError(413, "quota_exceeded", "Payload Too Large"),
			docError(422, "checksum_mismatch", "Unprocessable Entity"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:      "GET",
		Path:        "/api/v1/buckets/{bucket}/objects/*",
		Tag:         "Objects",
		Summary:     "Download an object",
		Description: "Use to download an object's bytes. The key is the trailing wildcard path segment, percent-decoded once. Success is 200 with the full object body. The response streams the blob with the stored Content-Type (default application/octet-stream), ETag (quoted lowercase SHA-256), X-Filehouse-SHA256 (bare digest), one `X-Filehouse-Meta-<Name>` header per stored metadata entry, and the Last-Modified, Accept-Ranges and Content-Length headers. A Range request answers 206 with Content-Range and an unsatisfiable range is 416; conditional reads are supported through If-None-Match / If-Modified-Since, which answer 304 without a body, If-Match / If-Unmodified-Since, whose mismatch is 412, and If-Range. The 304, 412 and 416 outcomes come from the standard HTTP content server and carry no problem document. ?download=1 adds Content-Disposition: attachment with the key's basename as the filename. Requires read permission on the bucket; unknown keys are 404 object_not_found.",
		Security:    "bearer",
		Response:    docBinaryResponse,
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_key", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "object_not_found", "Not Found"),
			apidocs.ErrorDoc{Status: 412, Title: "Precondition Failed"},
			apidocs.ErrorDoc{Status: 416, Title: "Range Not Satisfiable"},
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:      "HEAD",
		Path:        "/api/v1/buckets/{bucket}/objects/*",
		Tag:         "Objects",
		Summary:     "Read object metadata",
		Description: "Use to read an object's headers without transferring its bytes. The route shares the download handler: it performs the same key validation and authorization and returns the same status and headers as GET (Content-Type, ETag, X-Filehouse-SHA256, `X-Filehouse-Meta-<Name>`, Last-Modified, Accept-Ranges, Content-Length) with an empty body. Range and conditional requests behave as on GET: 206 for a satisfiable range, 416 for an unsatisfiable one, 304 for a matching If-None-Match / If-Modified-Since and 412 for a failing If-Match / If-Unmodified-Since; these outcomes carry no problem document. Requires read permission on the bucket; unknown keys are 404 object_not_found.",
		Security:    "bearer",
		Response:    docBinaryResponse,
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_key", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "object_not_found", "Not Found"),
			apidocs.ErrorDoc{Status: 412, Title: "Precondition Failed"},
			apidocs.ErrorDoc{Status: 416, Title: "Range Not Satisfiable"},
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:      "DELETE",
		Path:        "/api/v1/buckets/{bucket}/objects/*",
		Tag:         "Objects",
		Summary:     "Delete an object",
		Description: "Use to delete one object. The metadata row, the blob refcount and the bucket counters are updated in one transaction and success is 204 with no body. The blob file itself is not removed here: the reaper deletes it once the refcount reaches zero and the GC grace period has passed, so the bytes of a deleted object can still back a deduplicated copy. Requires delete permission on the bucket; a key outside the key grammar is 400 invalid_key and an unknown key is 404 object_not_found.",
		Security:    "bearer",
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_key", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "object_not_found", "Not Found"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
}
