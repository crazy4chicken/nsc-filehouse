package httpapi

import apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

// docSelfOperations documents the caller-scoped endpoints. Both read only the
// subject carried by the verified token and run no permission cascade, so the
// deriver yields no required key for either route: a valid bearer token is
// enough.
var docSelfOperations = []apidocs.Operation{
	{
		Method:      "GET",
		Path:        "/api/v1/usage",
		Tag:         "Self-service",
		Summary:     "Get your usage",
		Description: "Use to review your own storage consumption and quota. The subject always comes from the verified token, so a caller can never read another subject's usage. used_bytes and used_objects aggregate every bucket owned by the subject across owner kinds; buckets repeats those figures per bucket together with each bucket's own quota. quota_bytes and quota_objects are the subject-level quota row stored under kind user - a missing row, or a zero field, means unlimited. No permission grant is required beyond a valid bearer token.",
		Security:    "bearer",
		Response:    usageResponse{},
		ResponseExample: map[string]any{
			"subject":       map[string]any{"id": "01J8ZQ4F7G9K2M3N4P5Q6R7S8T", "kind": "user"},
			"used_bytes":    734003200,
			"used_objects":  42,
			"quota_bytes":   10737418240,
			"quota_objects": 250000,
			"buckets": []any{
				map[string]any{
					"bucket_id":           "01J8ZR2M5T7V9W1X3Y5Z7A9B1C",
					"bucket_name":         "team-avatars",
					"owner_id":            "01J8ZQ4F7G9K2M3N4P5Q6R7S8T",
					"owner_kind":          "user",
					"team_id":             "01J8ZP2Q4R6S8T0V2W4X6Y8ZB",
					"used_bytes":          734003200,
					"used_objects":        42,
					"quota_bytes":         10737418240,
					"quota_objects":       250000,
					"subject_max_bytes":   10737418240,
					"subject_max_objects": 250000,
				},
			},
		},
		Errors: []apidocs.ErrorDoc{docUnauthorized, docServiceUnavailable},
	},
	{
		Method:      "GET",
		Path:        "/api/v1/me/permissions",
		Tag:         "Self-service",
		Summary:     "List your permissions",
		Description: "Use to inspect the grants teamusers reports for your subject. Keys are canonical [!]resource:action:scope strings sorted lexicographically; revoked grants keep their leading ! and wildcard segments are preserved. Grants are never inferred from the token contents: the list is resolved through the IAM permission cache, which only reuses an entry while its perm_ver matches the token. No permission grant is required beyond a valid bearer token. When the lookup fails the endpoint answers 503 iam_unavailable - it fails closed and the list is never guessed.",
		Security:    "bearer",
		Response:    permissionsResponse{},
		ResponseExample: map[string]any{
			"subject": map[string]any{"id": "01J8ZQ4F7G9K2M3N4P5Q6R7S8T", "kind": "user"},
			"permissions": []any{
				"!filehouse:manage:any",
				"filehouse:delete:own",
				"filehouse:read:own",
				"filehouse:read:team",
				"filehouse:share:own",
				"filehouse:write:own",
				"filehouse:write:team",
			},
		},
		Errors: []apidocs.ErrorDoc{docUnauthorized, docIAMUnavailable},
	},
}
