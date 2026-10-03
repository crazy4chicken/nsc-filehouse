package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
)

const readinessTimeout = 5 * time.Second

type statusResponse struct {
	Status string `json:"status"`
}

// routePublic registers the dependency reporting endpoints: liveness always
// answers 200, readiness checks PostgreSQL and the blob directory.
func (s *Server) routePublic(r chi.Router) {
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.opts.Store == nil || s.opts.Blobs == nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()
	if err := s.opts.Store.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", "check", "postgres", "error", err)
		httpx.WriteJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "unavailable"})
		return
	}
	if err := s.opts.Blobs.Writable(); err != nil {
		s.log.Warn("readiness check failed", "check", "blob-dir", "error", err)
		httpx.WriteJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "unavailable"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, statusResponse{Status: "ready"})
}
