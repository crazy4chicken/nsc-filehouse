// OpenAPI metadata for the filehouse HTTP surface.
//
// Each route registered by this package is described by exactly one
// apidocs.Operation, grouped by area in the doc_*.go files next to this one:
// doc_system.go, doc_buckets.go, doc_objects.go, doc_uploads.go,
// doc_presign.go, doc_self.go and doc_admin.go. DocOperations concatenates the
// seven groups, and cmd/genspec matches the result against the live chi router
// by method and path, so a route without metadata - or metadata without a
// route - fails generation instead of silently drifting from the
// specification.
//
// The declarations below are shared with every group file: authenticated
// operations reuse the same 401, 403, 503 and idempotency-conflict problems,
// and operations that stream raw bytes reuse docBinaryResponse, so the emitted
// document stays identical wherever the contract is identical.
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"
)

// docError creates the problem metadata emitted for one documented failure.
func docError(status int, code, title string) apidocs.ErrorDoc {
	return apidocs.ErrorDoc{Status: status, Code: code, Title: title}
}

// Problem responses shared by every group of operations. Titles are the HTTP
// status text and codes are the stable problem detail values, so together they
// form one source of truth for the error contract.
var (
	docUnauthorized          = docError(401, "invalid_token", "Unauthorized")
	docForbidden             = docError(403, "insufficient_permissions", "Forbidden")
	docIAMUnavailable        = docError(503, "iam_unavailable", "Service Unavailable")
	docServiceUnavailable    = docError(503, "service_unavailable", "Service Unavailable")
	docIdempotencyConflict   = docError(422, "idempotency_conflict", "Unprocessable Entity")
	docIdempotencyInProgress = docError(409, "idempotency_in_progress", "Conflict")
)

// docBinaryResponse is the placeholder response of operations that stream raw
// object bytes instead of JSON. Reflection cannot describe an octet stream, so
// the generator emits a schema-less 200 for it; the operation description
// carries the real byte contract - response headers, Range requests and
// conditional semantics.
var docBinaryResponse = json.RawMessage{}

// DocOperations is the complete route metadata of the service in group order:
// system, buckets, objects, uploads, presign, self-service and admin. It is
// the input of cmd/genspec, which validates it against the live chi router and
// emits the OpenAPI document.
var DocOperations = apidocs.All(
	docSystemOperations,
	docBucketOperations,
	docObjectOperations,
	docUploadOperations,
	docPresignOperations,
	docSelfOperations,
	docAdminOperations,
)

// DocPermission derives the any- and team-scoped permission keys an operation
// requires from its method and path. cmd/genspec passes it to apidocs.Collect,
// which stores the result in the x-teamusers-permission extension of every
// operation.
//
// The rules mirror the handler decisions:
//
//   - /api/v1/buckets* uses the verb of the request method - read for GET and
//     HEAD, write for PUT, POST and PATCH, delete for DELETE - and requires the
//     matching any- and team-scoped keys; own-scoped grants are resolved
//     against the concrete bucket at request time. Upload paths are the
//     exception: their reads stay read, but the abort DELETE is enforced as a
//     write, so every non-read upload method derives the write keys.
//   - /api/v1/admin/* always requires filehouse:manage:any and is never team
//     scoped.
//   - POST /api/v1/presign requires the share keys; the handler additionally
//     requires the method verb (read for GET and HEAD, write for PUT), which
//     the route metadata documents in its permission note.
//   - /healthz, /readyz, /presign/{bucket}/*, /api/v1/usage and
//     /api/v1/me/permissions need no key: they are public, or scoped to the
//     calling subject by authentication alone.
//
// A method or path outside these rules derives nothing, and the operation is
// emitted without a permission extension.
func DocPermission(method, path string) (anyKey, teamKey string) {
	switch {
	case path == "/api/v1/presign":
		return "filehouse:share:any", "filehouse:share:team"
	case strings.HasPrefix(path, "/api/v1/admin/"):
		return "filehouse:manage:any", ""
	case strings.HasPrefix(path, "/api/v1/buckets/") && strings.Contains(path, "/uploads"):
		// Aborting an upload is enforced as a write, so DELETE maps to write as well.
		if m := strings.ToUpper(method); m == http.MethodGet || m == http.MethodHead {
			return "filehouse:read:any", "filehouse:read:team"
		}
		return "filehouse:write:any", "filehouse:write:team"
	case strings.HasPrefix(path, "/api/v1/buckets"):
		var verb string
		switch strings.ToUpper(method) {
		case http.MethodGet, http.MethodHead:
			verb = "read"
		case http.MethodPut, http.MethodPost, http.MethodPatch:
			verb = "write"
		case http.MethodDelete:
			verb = "delete"
		}
		if verb == "" {
			return "", ""
		}
		return "filehouse:" + verb + ":any", "filehouse:" + verb + ":team"
	default:
		return "", ""
	}
}
