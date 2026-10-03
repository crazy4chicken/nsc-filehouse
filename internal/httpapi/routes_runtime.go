package httpapi

import "github.com/go-chi/chi/v5"

// routeRuntime registers the subject facing API: buckets, objects, multipart
// uploads and the self endpoints. The router passed in already enforces bearer
// authentication and POST idempotency, so the handlers only decide
// authorization. Paths are absolute because the group is mounted at the root.
func (s *Server) routeRuntime(r chi.Router) {
	r.Get("/api/v1/buckets", s.handleListBuckets)
	r.Post("/api/v1/buckets", s.handleCreateBucket)
	r.Get("/api/v1/buckets/{bucket}", s.handleGetBucket)
	r.Patch("/api/v1/buckets/{bucket}", s.handlePatchBucket)
	r.Delete("/api/v1/buckets/{bucket}", s.handleDeleteBucket)

	r.Get("/api/v1/buckets/{bucket}/objects", s.handleListObjects)
	r.Put("/api/v1/buckets/{bucket}/objects/*", s.handlePutObject)
	r.Get("/api/v1/buckets/{bucket}/objects/*", s.handleGetObject)
	r.Head("/api/v1/buckets/{bucket}/objects/*", s.handleGetObject)
	r.Delete("/api/v1/buckets/{bucket}/objects/*", s.handleDeleteObject)

	r.Post("/api/v1/buckets/{bucket}/uploads", s.handleInitiateUpload)
	r.Get("/api/v1/buckets/{bucket}/uploads/{uploadID}", s.handleGetUpload)
	r.Delete("/api/v1/buckets/{bucket}/uploads/{uploadID}", s.handleAbortUpload)
	r.Put("/api/v1/buckets/{bucket}/uploads/{uploadID}/parts/{partNo}", s.handlePutUploadPart)
	r.Post("/api/v1/buckets/{bucket}/uploads/{uploadID}/complete", s.handleCompleteUpload)

	r.Get("/api/v1/usage", s.handleUsage)
	r.Get("/api/v1/me/permissions", s.handlePermissions)
}
