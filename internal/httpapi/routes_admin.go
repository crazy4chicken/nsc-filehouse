package httpapi

import "github.com/go-chi/chi/v5"

// routeAdmin registers the authenticated management plane: presigned URL
// minting plus the platform-wide admin endpoints.
//
// The router this is mounted on already installs bearer authentication and the
// Idempotency-Key middleware, so every handler below can rely on verified
// claims and every path is absolute.
func (s *Server) routeAdmin(r chi.Router) {
	r.Post("/api/v1/presign", s.handlePresignMint)
	r.Get("/api/v1/admin/stats", s.handleAdminStats)
	r.Get("/api/v1/admin/quotas", s.handleAdminListQuotas)
	r.Put("/api/v1/admin/quotas/{kind}/{id}", s.handleAdminPutQuota)
	r.Post("/api/v1/admin/gc", s.handleAdminGC)
}
