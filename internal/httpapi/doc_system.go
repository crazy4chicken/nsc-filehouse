package httpapi

import apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

// docSystemOperations documents the public dependency reporting endpoints.
// Both routes are unauthenticated and perform no authorization decision, so
// the permission deriver yields no required key for either of them.
var docSystemOperations = []apidocs.Operation{
	{
		Method:          "GET",
		Path:            "/healthz",
		Tag:             "System",
		Summary:         "Liveness probe",
		Description:     "Use to check that the process is alive. Always answers 200 with the plain JSON body {\"status\":\"ok\"} while the process is serving; it performs no dependency checks, so PostgreSQL, IAM and the blob directory are never consulted. Suitable as a Kubernetes liveness probe; use GET /readyz when traffic gating matters. Public endpoint: no Authorization header is required.",
		Security:        "",
		Response:        statusResponse{},
		ResponseExample: map[string]any{"status": "ok"},
	},
	{
		Method:          "GET",
		Path:            "/readyz",
		Tag:             "System",
		Summary:         "Readiness probe",
		Description:     "Use to check that the service can accept traffic. Two dependencies are verified: PostgreSQL must answer a ping within five seconds, and the blob directory must be writable. On success the endpoint answers 200 with {\"status\":\"ready\"}. When either check fails it answers 503 with the plain JSON body {\"status\":\"unavailable\"} - this response is not a problem+json document and carries no detail code - and the failing check (postgres or blob-dir) is recorded in the server log. Public endpoint: no Authorization header is required.",
		Security:        "",
		Response:        statusResponse{},
		ResponseExample: map[string]any{"status": "ready"},
	},
}
