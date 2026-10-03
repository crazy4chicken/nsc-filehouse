package httpapi

import "github.com/go-chi/chi/v5"

// routePresignPublic registers the public presigned URL redemption surface.
//
// The routes are mounted on the root router and therefore carry no bearer
// authentication: the signed token in the ?sig= query parameter is the only
// credential. GET tokens also authorize HEAD; PUT requires a token minted for
// PUT, so a read link can never be replayed as a write.
//
// chi v5 has no "{key...}" catch-all, so the object key is the trailing
// wildcard: "/presign/{bucket}/*" with the key read from chi.URLParam(r, "*").
func (s *Server) routePresignPublic(r chi.Router) {
	r.Get("/presign/{bucket}/*", s.handlePresignRedeem)
	r.Head("/presign/{bucket}/*", s.handlePresignRedeem)
	r.Put("/presign/{bucket}/*", s.handlePresignRedeem)
}
