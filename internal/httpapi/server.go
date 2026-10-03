// Package httpapi exposes the filehouse HTTP surface on a chi router.
package httpapi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crazy4chicken/nsc-filehouse/internal/blob"
	"github.com/crazy4chicken/nsc-filehouse/internal/config"
	"github.com/crazy4chicken/nsc-filehouse/internal/gc"
	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
	"github.com/crazy4chicken/nsc-filehouse/internal/iamauth"
	"github.com/crazy4chicken/nsc-filehouse/internal/presign"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// Options carries every dependency of the HTTP layer. Store, Blobs, Authorizer,
// Signer and Reaper are required to serve traffic; readyz reports the service as
// unavailable when the store or the blob store is missing.
type Options struct {
	Config     *config.Config
	Store      *store.Store
	Blobs      *blob.Store
	Authorizer *iamauth.Authorizer
	Signer     *presign.Signer
	Logger     *slog.Logger
	Version    string
	Reaper     *gc.Reaper
}

// Server owns the router and its dependencies.
type Server struct {
	opts Options
	log  *slog.Logger
}

// NewServer builds a server from its dependencies.
func NewServer(o Options) *Server {
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{opts: o, log: log}
}

// Config returns the effective configuration.
func (s *Server) Config() *config.Config { return s.opts.Config }

// Store returns the metadata store.
func (s *Server) Store() *store.Store { return s.opts.Store }

// Blobs returns the blob store.
func (s *Server) Blobs() *blob.Store { return s.opts.Blobs }

// Authorizer returns the teamusers authorizer.
func (s *Server) Authorizer() *iamauth.Authorizer { return s.opts.Authorizer }

// Signer returns the presign signer.
func (s *Server) Signer() *presign.Signer { return s.opts.Signer }

// Reaper returns the garbage collector.
func (s *Server) Reaper() *gc.Reaper { return s.opts.Reaper }

// Logger returns the server logger.
func (s *Server) Logger() *slog.Logger { return s.log }

// Version returns the build version.
func (s *Server) Version() string { return s.opts.Version }

// Handler builds the chi router: Recover, RequestID and AccessLog wrap every
// route, /healthz and /readyz stay public, the /api/v1 group requires a bearer
// token and idempotent POSTs, and the presign redemption routes are public.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(Recover(s.log))
	router.Use(RequestID)
	router.Use(AccessLog(s.log))
	router.Use(ClientIP(s.trustedProxies()))
	s.routes(router)
	return router
}

// routes mounts every route group. Runtime and admin handlers come from the
// handler files; groups are inline so those files register absolute paths.
func (s *Server) routes(r chi.Router) {
	s.routePublic(r)
	r.Group(func(authenticated chi.Router) {
		if s.opts.Authorizer != nil {
			authenticated.Use(s.opts.Authorizer.Authenticate)
		}
		var idempotent store.IdempotencyStore
		if s.opts.Store != nil {
			idempotent = s.opts.Store
		}
		authenticated.Use(Idempotency(idempotent, s.idempotencyTTL()))
		s.routeRuntime(authenticated)
		s.routeAdmin(authenticated)
	})
	s.routePresignPublic(r)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "", "invalid_request")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, http.StatusMethodNotAllowed, "", "invalid_request")
	})
}

func (s *Server) trustedProxies() []netip.Prefix {
	if s.opts.Config == nil {
		return nil
	}
	return s.opts.Config.TrustedProxies
}

func (s *Server) idempotencyTTL() time.Duration {
	if s.opts.Config == nil || s.opts.Config.IdempotencyTTL <= 0 {
		return config.DefaultIdempotencyTTL
	}
	return s.opts.Config.IdempotencyTTL
}
