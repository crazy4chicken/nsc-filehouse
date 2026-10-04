package httpapi

import (
	apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// docPresignMintRequest mirrors presignMintRequest for documentation: the
// optional fields carry omitempty so bucket, key, and method are the only
// required properties of the generated schema.
type docPresignMintRequest struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	Method      string `json:"method"`
	TTLSeconds  int64  `json:"ttl_seconds,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	MaxBytes    int64  `json:"max_bytes,omitempty"`
}

// docPresignOperations documents presigned URL minting and the public
// redemption surface.
var docPresignOperations = []apidocs.Operation{
	{
		Method:  "POST",
		Path:    "/api/v1/presign",
		Tag:     "Presign",
		Summary: "Mint a presigned URL",
		Description: "Use to mint one time-limited, signature-checked URL so a client without a bearer token can download or upload a single object. " +
			"The method must be GET, HEAD, or PUT (trimmed and uppercased); the token is bound to that method, the bucket, and the key, so a read link can never be replayed as a write " +
			"and a GET token also authorizes HEAD. Minting requires both the share grant and the grant the URL will exercise (read for GET/HEAD, write for PUT) on the same bucket. " +
			"ttl_seconds may be omitted or 0 for the configured default (15m), must not be negative, and must not exceed the configured maximum (24h); the token stores whole Unix seconds, so it never lives longer than requested. " +
			"content_type (at most 255 bytes, no control characters) is signed and written back by a PUT redemption, and max_bytes caps a PUT body in addition to the object limit (5 GiB by default); 0 means no token-level cap. " +
			"The returned url origin is public_base_url when configured; otherwise it is built from the request scheme and the Host header, which is client controlled - deployments behind a proxy that rewrites Host must set public_base_url, and a missing Host answers 500. " +
			"The signed payload embeds the subject, kind, team, and perm_ver, so redemption re-checks current permissions and a permission or version change invalidates outstanding URLs (403 insufficient_permissions, reason permissions changed). " +
			"The URL is not single-use: anyone holding it can redeem it repeatedly until the token expires, subject to that permission recheck. " +
			"Idempotency-Key makes retries safe.",
		PermissionNote: "Minting requires both filehouse:share:{any,team} and the grant the URL will exercise: filehouse:read:{any,team} for GET or HEAD, or filehouse:write:{any,team} for PUT, evaluated against the same bucket resource.",
		Security:       "bearer",
		Request:        docPresignMintRequest{},
		RequestExample: map[string]any{
			"bucket":       "media",
			"key":          "recordings/2026/10/03/lecture-04.mp4",
			"method":       "PUT",
			"ttl_seconds":  int64(3600),
			"content_type": "video/mp4",
			"max_bytes":    int64(268435456),
		},
		Response: presignMintResponse{},
		ResponseExample: map[string]any{
			"url":        "https://files.example.com/presign/media/recordings/2026/10/03/lecture-04.mp4?sig=eyJidWNrZXQiOiJtZWRpYSIsImtleSI6InJlY29yZGluZ3MvMjAyNi8xMC8wMy9sZWN0dXJlLTA0Lm1wNCIsIm1ldGhvZCI6IlBVVCIsInN1YmplY3QiOiIwMUo4WlE0RjdHOUsyTTNONFA1UTZSN1M4ViIsImtpbmQiOiJ1c2VyIiwicGVybV92ZXIiOjcsImV4cCI6MTc5MTEyMTIwMCwiY29udGVudF90eXBlIjoidmlkZW8vbXA0IiwibWF4X2J5dGVzIjoyNjg0MzU0NTZ9.UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw",
			"method":     "PUT",
			"bucket":     "media",
			"key":        "recordings/2026/10/03/lecture-04.mp4",
			"expires_at": "2026-10-04T10:20:00Z",
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_key", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docIdempotencyInProgress,
			docIdempotencyConflict,
			docError(500, "service_unavailable", "Internal Server Error"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:  "GET",
		Path:    "/presign/{bucket}/*",
		Tag:     "Presign",
		Summary: "Download an object with a presigned URL",
		Description: "Use to download one object with the sig query parameter token instead of a bearer token; no Authorization header is involved. " +
			"The token is checked before the store is touched: missing, malformed, forged, or method/bucket/key-mismatched tokens all answer 403 presign_invalid, and an expired token answers 410 presign_expired. " +
			"Bucket and object existence are only disclosed after the subject embedded in the signature is re-authorized against the current permissions with its perm_ver, so a permission or version change invalidates outstanding URLs with 403 insufficient_permissions (reason permissions changed). " +
			"A token minted for GET also authorizes HEAD; a PUT requires a token minted for PUT. The response is the raw object bytes with the stored Content-Type and the ETag, X-Filehouse-SHA256, and X-Filehouse-Meta-* headers; " +
			"Range requests answer 206 with Content-Range, an unsatisfiable range answers 416, If-None-Match/If-Modified-Since answer 304, a failing If-Match/If-Unmodified-Since answers 412, and download=1 adds an attachment Content-Disposition.",
		Security: "",
		Response: docBinaryResponse,
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(403, "presign_invalid", "Forbidden"),
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "object_not_found", "Not Found"),
			docError(410, "presign_expired", "Gone"),
			apidocs.ErrorDoc{Status: 412, Title: "Precondition Failed"},
			apidocs.ErrorDoc{Status: 416, Title: "Range Not Satisfiable"},
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:  "HEAD",
		Path:    "/presign/{bucket}/*",
		Tag:     "Presign",
		Summary: "Read object headers with a presigned URL",
		Description: "Use to read one object's headers, including existence, size, digest, and stored metadata, with the sig query parameter token without transferring the body. " +
			"It runs exactly the same signature, expiry, permission-recheck, and object-existence checks as the GET redemption and answers the same statuses with headers only: 200 on success, " +
			"206 or 416 for Range requests, 304 for If-None-Match/If-Modified-Since, and 412 for a failing If-Match/If-Unmodified-Since. " +
			"A token minted for GET also authorizes HEAD; a token minted for PUT never serves reads. Failures match the GET redemption: 403 presign_invalid for a missing or non-matching token, " +
			"410 presign_expired after expiry, 403 insufficient_permissions when the signed subject no longer holds the grant, 404 bucket_not_found or object_not_found only after authorization, and 503 when the signer, store, or IAM dependency is unavailable.",
		Security: "",
		Response: docBinaryResponse,
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(403, "presign_invalid", "Forbidden"),
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(404, "object_not_found", "Not Found"),
			docError(410, "presign_expired", "Gone"),
			apidocs.ErrorDoc{Status: 412, Title: "Precondition Failed"},
			apidocs.ErrorDoc{Status: 416, Title: "Range Not Satisfiable"},
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
	{
		Method:  "PUT",
		Path:    "/presign/{bucket}/*",
		Tag:     "Presign",
		Summary: "Upload an object with a presigned URL",
		Description: "Use to upload one object with the sig query parameter token instead of a bearer token; the token must have been minted for PUT, because a GET or HEAD token cannot write. " +
			"The request body is the raw object bytes, not JSON, and the object size limit (5 GiB by default) applies; a max_bytes value signed into the token is enforced in addition, and either cap answers 413 payload_too_large. " +
			"The content type written is the value signed into the token, falling back to the request Content-Type and then application/octet-stream; X-Filehouse-SHA256 is honored (a mismatch answers 422 checksum_mismatch) and X-Filehouse-Meta-* headers are stored as object metadata. " +
			"The write is committed through the same quota-enforcing path as an authenticated PUT: an existing key is replaced (still 201), quota rejections answer 413 quota_exceeded, and the response is the full object JSON with ETag and X-Filehouse-SHA256 headers. " +
			"Redemption re-authorizes the subject embedded in the signature with its perm_ver, so a permission change makes outstanding tokens fail with 403 insufficient_permissions before any bytes are read.",
		Security: "",
		Request:  nil,
		Response: store.Object{},
		ResponseExample: map[string]any{
			"bucket_id":    "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
			"key":          "recordings/2026/10/03/lecture-04.mp4",
			"blob_hash":    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			"size":         int64(268435456),
			"etag":         "\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"",
			"content_type": "video/mp4",
			"owner_id":     "01J8ZQ4F7G9K2M3N4P5Q6R7S8V",
			"metadata":     map[string]string{"course": "cs-101", "source": "lecture-capture"},
			"created_at":   "2026-10-04T10:18:02Z",
			"updated_at":   "2026-10-04T10:18:02Z",
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "invalid_bucket_name", "Invalid Request"),
			docError(400, "invalid_request", "Invalid Request"),
			docError(403, "presign_invalid", "Forbidden"),
			docForbidden,
			docError(404, "bucket_not_found", "Not Found"),
			docError(410, "presign_expired", "Gone"),
			docError(413, "payload_too_large", "Payload Too Large"),
			docError(413, "quota_exceeded", "Payload Too Large"),
			docError(422, "checksum_mismatch", "Unprocessable Entity"),
			docIAMUnavailable,
			docServiceUnavailable,
		},
	},
}
