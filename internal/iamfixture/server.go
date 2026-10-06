// Package iamfixture is a self-contained fake teamusers instance for
// integration tests.
//
// The fixture generates an Ed25519 key at construction and serves the
// endpoints the official teamusers Go SDK talks to:
//
//	GET  /.well-known/jwks.json
//	GET  /authz/permissions/{userID}?version=2
//	POST /authz/check
//	POST /auth/client-credentials
//	POST /permissions/
//
// The permission endpoint mirrors the server contract the SDK relies on: only
// the version 2 snapshot is served, and a missing or legacy version answers
// HTTP 400 instead of a flattened response.
//
// It mints compact EdDSA JWTs with the standard library only and evaluates the
// subset of the teamusers permission semantics the filehouse contract
// relies on: segment-wise matching where "*" matches exactly one segment, an
// explicit "!" deny that beats every allow, and a small ABAC condition
// evaluator that fails closed on anything outside its grammar.
package iamfixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Defaults used when NewServer receives a zero Options value.
const (
	// DefaultClientID and DefaultClientSecret are accepted by
	// POST /auth/client-credentials unless SetCredentials replaces them.
	DefaultClientID     = "filehouse"
	DefaultClientSecret = "filehouse-test-secret"
	// DefaultIssuer and DefaultAudience match the SDK defaults.
	DefaultIssuer   = "teamusers"
	DefaultAudience = "teamusers"
	// DefaultKeyID is the kid of the generated Ed25519 key.
	DefaultKeyID = "filehouse-test-key"

	defaultTokenTTL = 15 * time.Minute
	// serviceTokenLifetimeSeconds is the expires_in advertised by the
	// client-credentials endpoint.
	serviceTokenLifetimeSeconds = 3600
)

// Grant is one permission grant served to the SDK. Condition is the ABAC
// condition source in the restricted grammar; an empty condition matches
// unconditionally.
type Grant struct {
	Key       string `json:"key"`
	Condition string `json:"condition,omitempty"`
}

// Options configures NewServer. Zero fields select the documented defaults.
type Options struct {
	Issuer       string
	Audience     string
	KeyID        string
	ClientID     string
	ClientSecret string
	TokenTTL     time.Duration
}

// Server is the fake teamusers instance. It listens on 127.0.0.1 with a kernel
// assigned port, so tests never collide on fixed ports.
type Server struct {
	issuer   string
	audience string
	kid      string

	private ed25519.PrivateKey
	public  ed25519.PublicKey

	listener   net.Listener
	httpServer *http.Server
	handler    http.Handler
	baseURL    string

	clientID     string
	clientSecret string

	mu           sync.Mutex
	grants       map[string]subjectState
	registered   []string
	tokenTTL     time.Duration
	expireTokens bool

	now func() time.Time
}

// subjectState is the permission set of one subject.
type subjectState struct {
	permVer int64
	grants  []Grant
}

// New starts a fixture with default options.
func New() (*Server, error) {
	return NewServer(Options{})
}

// NewServer generates the signing key and starts the HTTP listener.
func NewServer(options Options) (*Server, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("iamfixture: generate signing key: %w", err)
	}
	if options.Issuer == "" {
		options.Issuer = DefaultIssuer
	}
	if options.Audience == "" {
		options.Audience = DefaultAudience
	}
	if options.KeyID == "" {
		options.KeyID = DefaultKeyID
	}
	if options.ClientID == "" {
		options.ClientID = DefaultClientID
	}
	if options.ClientSecret == "" {
		options.ClientSecret = DefaultClientSecret
	}
	if options.TokenTTL <= 0 {
		options.TokenTTL = defaultTokenTTL
	}

	server := &Server{
		issuer:       options.Issuer,
		audience:     options.Audience,
		kid:          options.KeyID,
		private:      private,
		public:       public,
		clientID:     options.ClientID,
		clientSecret: options.ClientSecret,
		grants:       make(map[string]subjectState),
		tokenTTL:     options.TokenTTL,
		now:          time.Now,
	}
	server.handler = server.routes()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("iamfixture: listen: %w", err)
	}
	server.listener = listener
	server.baseURL = "http://" + listener.Addr().String()
	server.httpServer = &http.Server{
		Handler:           server.handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = server.httpServer.Serve(listener)
	}()
	return server, nil
}

// URL returns the fixture base URL, for example http://127.0.0.1:54321.
func (s *Server) URL() string {
	return s.baseURL
}

// Handler returns the fixture HTTP handler for callers that prefer to drive it
// through httptest.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Close stops the fixture listener.
func (s *Server) Close() error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	return s.httpServer.Close()
}

// SetCredentials replaces the client id and secret accepted by the
// client-credentials endpoint.
func (s *Server) SetCredentials(clientID, clientSecret string) {
	s.mu.Lock()
	s.clientID = clientID
	s.clientSecret = clientSecret
	s.mu.Unlock()
}

// SetGrants replaces the permission set and permission version of one subject.
// The grants slice is copied.
func (s *Server) SetGrants(subject string, permVer int64, grants ...Grant) {
	set := make([]Grant, len(grants))
	copy(set, grants)
	s.mu.Lock()
	s.grants[subject] = subjectState{permVer: permVer, grants: set}
	s.mu.Unlock()
}

// SetPermVer changes the permission version of a subject, keeping its grants.
func (s *Server) SetPermVer(subject string, permVer int64) {
	s.mu.Lock()
	state := s.grants[subject]
	state.permVer = permVer
	s.grants[subject] = state
	s.mu.Unlock()
}

// BumpPermVer increments and returns the permission version of a subject,
// which invalidates every token or presigned URL signed with the old version.
func (s *Server) BumpPermVer(subject string) int64 {
	s.mu.Lock()
	state := s.grants[subject]
	state.permVer++
	s.grants[subject] = state
	permVer := state.permVer
	s.mu.Unlock()
	return permVer
}

// Permissions returns a copy of the grants and permission version of a subject.
func (s *Server) Permissions(subject string) (int64, []Grant) {
	s.mu.Lock()
	state := s.grants[subject]
	s.mu.Unlock()
	grants := make([]Grant, len(state.grants))
	copy(grants, state.grants)
	return state.permVer, grants
}

// RegisteredPermissions returns the permission keys POSTed to /permissions/.
func (s *Server) RegisteredPermissions() []string {
	s.mu.Lock()
	keys := make([]string, len(s.registered))
	copy(keys, s.registered)
	s.mu.Unlock()
	return keys
}

// routes builds the fixture mux.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /authz/permissions/{userID}", s.handlePermissions)
	mux.HandleFunc("POST /authz/check", s.handleCheck)
	mux.HandleFunc("POST /auth/client-credentials", s.handleClientCredentials)
	mux.HandleFunc("POST /permissions/", s.handleRegisterPermission)
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jwkSet{Keys: []jwkKey{s.publicJWK()}})
}

func (s *Server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	if !hasServiceToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "service token is required"})
		return
	}
	// The SDK requests the v2 snapshot and fails closed on any other version,
	// so a legacy request is rejected the way teamusers rejects it.
	if r.URL.Query().Get("version") != "2" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "unsupported permissions snapshot version"})
		return
	}
	userID := r.PathValue("userID")
	s.mu.Lock()
	state := s.grants[userID]
	s.mu.Unlock()
	grants := make([]Grant, len(state.grants))
	copy(grants, state.grants)
	writeJSON(w, http.StatusOK, struct {
		Version int     `json:"version"`
		UserID  string  `json:"user_id"`
		PermVer int64   `json:"perm_ver"`
		Grants  []Grant `json:"grants"`
	}{Version: 2, UserID: userID, PermVer: state.permVer, Grants: grants})
}

// checkRequest is the body of POST /authz/check. It carries the fields the
// teamusers authorization endpoint accepts; the SDK sends subject, permission
// and context.resource, while callers that need step-up enforcement also send
// auth_time and max_auth_age_seconds.
type checkRequest struct {
	Subject           string `json:"subject"`
	Permission        string `json:"permission"`
	AuthTime          int64  `json:"auth_time"`
	MaxAuthAgeSeconds int64  `json:"max_auth_age_seconds"`
	Context           struct {
		Resource struct {
			OwnerID string         `json:"owner_id"`
			TeamID  string         `json:"team_id"`
			Attrs   map[string]any `json:"attrs"`
		} `json:"resource"`
	} `json:"context"`
}

// checkResponse is the body of POST /authz/check.
type checkResponse struct {
	Allow   bool     `json:"allow"`
	Matched []string `json:"matched"`
	Reason  string   `json:"reason"`
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if !hasServiceToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "service token is required"})
		return
	}
	var request checkRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid_request"})
		return
	}
	if strings.TrimSpace(request.Subject) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid_request"})
		return
	}
	// Step-up enforcement: a request that asks for a maximum authentication age
	// is denied unless it carries a sufficiently recent auth_time.
	if request.MaxAuthAgeSeconds > 0 {
		age := s.now().Unix() - request.AuthTime
		if request.AuthTime <= 0 || age > request.MaxAuthAgeSeconds {
			writeJSON(w, http.StatusOK, checkResponse{Allow: false, Matched: []string{}, Reason: "step_up_required"})
			return
		}
	}
	allowed, matched, reason := s.evaluateCheck(request)
	writeJSON(w, http.StatusOK, checkResponse{Allow: allowed, Matched: matched, Reason: reason})
}

// evaluateCheck applies the teamusers permission semantics to one check.
func (s *Server) evaluateCheck(request checkRequest) (bool, []string, string) {
	requested, ok := splitPermissionKey(request.Permission)
	if !ok {
		return false, []string{}, "invalid permission"
	}
	s.mu.Lock()
	state := s.grants[request.Subject]
	grants := make([]Grant, len(state.grants))
	copy(grants, state.grants)
	s.mu.Unlock()

	context := evalContext{
		SubjectID: request.Subject,
		OwnerID:   request.Context.Resource.OwnerID,
		TeamID:    request.Context.Resource.TeamID,
		Attrs:     request.Context.Resource.Attrs,
	}
	matched := make([]string, 0, len(grants))
	allowed := false
	for _, grant := range grants {
		deny, granted, ok := splitGrantKey(grant.Key)
		if !ok || !segmentsMatch(granted, requested) {
			continue
		}
		matched = append(matched, grant.Key)
		condition, err := parseCondition(grant.Condition)
		if err != nil {
			// Unsupported condition syntax fails closed: the whole check denies.
			return false, matched, "condition denied"
		}
		applies, err := condition.eval(context)
		if err != nil {
			return false, matched, "condition denied"
		}
		if !applies {
			continue
		}
		if deny {
			// An explicit deny wins over every allow, no matter the order.
			return false, matched, "permission denied"
		}
		allowed = true
	}
	if allowed {
		return true, matched, "permission granted"
	}
	return false, matched, "no matching grant"
}

func (s *Server) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid_request"})
		return
	}
	s.mu.Lock()
	clientID, clientSecret := s.clientID, s.clientSecret
	s.mu.Unlock()
	if request.ClientID != clientID || request.ClientSecret != clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "invalid_client"})
		return
	}
	now := s.now()
	accessToken := s.Issue(Claims{
		Subject:   "service:filehouse",
		Kind:      "service",
		IssuedAt:  now,
		ExpiresAt: now.Add(serviceTokenLifetimeSeconds * time.Second),
	})
	refresh := make([]byte, 16)
	if _, err := rand.Read(refresh); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "entropy_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"expires_in":    serviceTokenLifetimeSeconds,
		"refresh_token": hex.EncodeToString(refresh),
		"token_type":    "Bearer",
	})
}

func (s *Server) handleRegisterPermission(w http.ResponseWriter, r *http.Request) {
	if !hasServiceToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "service token is required"})
		return
	}
	var request struct {
		Key          string `json:"key"`
		Description  string `json:"description"`
		RegisteredBy string `json:"registered_by"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&request); err != nil || strings.TrimSpace(request.Key) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid_request"})
		return
	}
	s.mu.Lock()
	known := false
	for _, key := range s.registered {
		if key == request.Key {
			known = true
			break
		}
	}
	if !known {
		s.registered = append(s.registered, request.Key)
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"key": request.Key})
}

// hasServiceToken reports whether the request carries a non-empty bearer token.
func hasServiceToken(r *http.Request) bool {
	parts := strings.Fields(r.Header.Get("Authorization"))
	return len(parts) == 2 && strings.EqualFold(parts[0], "bearer") && parts[1] != ""
}

// splitPermissionKey splits "resource:action:scope" and rejects deny prefixes.
func splitPermissionKey(key string) ([3]string, bool) {
	if strings.HasPrefix(strings.TrimSpace(key), "!") {
		return [3]string{}, false
	}
	parts := strings.Split(strings.TrimSpace(key), ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return [3]string{}, false
	}
	return [3]string{parts[0], parts[1], parts[2]}, true
}

// splitGrantKey splits a grant key and reports whether it is a deny.
func splitGrantKey(key string) (bool, [3]string, bool) {
	key = strings.TrimSpace(key)
	deny := strings.HasPrefix(key, "!")
	key = strings.TrimSpace(strings.TrimPrefix(key, "!"))
	segments, ok := splitPermissionKey(key)
	return deny, segments, ok
}

// segmentsMatch reports whether every grant segment matches the requested
// segment. "*" matches exactly one segment and never crosses a colon.
func segmentsMatch(grant, requested [3]string) bool {
	for i := range grant {
		if grant[i] != "*" && grant[i] != requested[i] {
			return false
		}
	}
	return true
}

// writeJSON marshals v and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"internal_error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
