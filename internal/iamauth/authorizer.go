// Package iamauth wires the nsc-teamusers Go SDK into nsc-filehouse:
// bearer-token authentication, the filehouse permission catalog, the scope
// cascade used for authorization decisions, and the service credential
// sources used to call teamusers.
//
// The package deliberately does not import internal/config; the command layer
// maps configuration values into Options.
package iamauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	iam "github.com/crazy4chicken/nsc-teamusers/sdk/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/httpx"
)

// Options configures the teamusers-backed Authorizer. The zero value is not
// usable: BaseURL is required.
type Options struct {
	// BaseURL is the teamusers base URL, for example https://iam.example.com.
	BaseURL string
	// Issuer is the expected access-token "iss" claim; empty selects the SDK
	// default ("teamusers").
	Issuer string
	// Audience is the expected access-token "aud" claim; empty selects the SDK
	// default ("teamusers").
	Audience string
	// ServiceToken is a static teamusers service token. When set it takes
	// precedence over the client-credentials pair.
	ServiceToken string
	// ClientID and ClientSecret enable the client-credentials exchange
	// (POST /auth/client-credentials) for short-lived service tokens.
	ClientID     string
	ClientSecret string
	// NATSURL optionally subscribes the permission cache and the JWKS cache to
	// teamusers invalidation events. NATS support requires the SDK nats build
	// tag; without it the subscription is reported as a warning and skipped.
	NATSURL string
	// Timeout bounds teamusers HTTP calls. It is applied only when HTTPClient
	// is nil; a non-positive value selects defaultHTTPTimeout.
	Timeout time.Duration
	// Logger receives startup warnings and degraded-mode notices. A nil logger
	// discards them.
	Logger *slog.Logger
	// HTTPClient optionally supplies the transport for IAM calls. When nil, a
	// client with Timeout is created.
	HTTPClient *http.Client
}

const (
	// defaultHTTPTimeout bounds IAM calls when Options.Timeout is unset.
	defaultHTTPTimeout = 10 * time.Second
	// resourceSegment is the permission resource owned by this service.
	resourceSegment = "filehouse"
	// policyDeniedReason is the SDK reason that marks an explicit deny; it is
	// terminal for the scope cascade.
	policyDeniedReason = "permission denied"
	// maxJWKSBytes bounds the JWKS response read during health checks.
	maxJWKSBytes = 1 << 20
)

// errAuthorizerUnavailable is returned when a decision is attempted on a
// partially constructed Authorizer. Every decision path fails closed.
var errAuthorizerUnavailable = errors.New("iam: authorizer is not configured")

// verbActions is the set of permission actions in the filehouse catalog.
var verbActions = map[string]struct{}{
	"read":   {},
	"write":  {},
	"delete": {},
	"share":  {},
	"manage": {},
}

// allowFunc evaluates one fully qualified permission key for the given claims
// against a resource and reports the SDK reason. Production code uses
// (*iam.Client).Allow; tests substitute it.
type allowFunc func(ctx context.Context, claims iam.Claims, permission string, resource iam.Resource) (bool, string)

// Authorizer authenticates bearer tokens and authorizes requests through the
// teamusers permission cascade.
type Authorizer struct {
	client      *iam.Client
	verifier    *iam.Verifier
	permissions *iam.PermissionsClient
	log         *slog.Logger
	httpClient  *http.Client
	baseURL     string

	subscriptions []*iam.PermissionSubscription
	allow         allowFunc
}

// Warnings reports non-fatal credential configuration problems so the command
// layer can surface them from `status` and `doctor` without failing startup.
func (o Options) Warnings() []string {
	var warnings []string
	staticToken := strings.TrimSpace(o.ServiceToken)
	if staticToken != "" && (o.ClientID != "" || o.ClientSecret != "") {
		warnings = append(warnings, "both a static IAM service token and IAM client credentials are configured; the static service token is used")
	}
	if (o.ClientID == "") != (o.ClientSecret == "") {
		warnings = append(warnings, "IAM client credentials are incomplete; set both the client id and the client secret")
	}
	if staticToken == "" && o.ClientID == "" && o.ClientSecret == "" {
		warnings = append(warnings, "no IAM service credential is configured; permission cache fills, authorization fallbacks, and permission registration will fail")
	}
	return warnings
}

// httpClient resolves the transport for IAM calls. A caller-supplied client is
// returned unchanged: its own Timeout governs, because Options.Timeout would
// require copying the client (and its mutex).
func (o Options) resolveHTTPClient() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &http.Client{Timeout: timeout}
}

// serviceTokenSource selects the service credential callback for the
// permissions client. It returns nil when no credential is configured, which
// makes the SDK fail closed on every permission lookup.
func serviceTokenSource(o Options, hc *http.Client) func() (string, error) {
	if token := strings.TrimSpace(o.ServiceToken); token != "" {
		return staticTokenSource{token: token}.Token
	}
	if o.ClientID != "" || o.ClientSecret != "" {
		return newClientCredentialsSource(o.BaseURL, o.ClientID, o.ClientSecret, hc, o.Timeout).Token
	}
	return nil
}

// NewAuthorizer builds the verified-token pipeline: a JWKS verifier, a
// permission cache with a service credential source, and the SDK client that
// combines them.
//
// The SDK client is intentionally left in its default mode: Allow evaluates
// the local permission cache first and falls back to POST /authz/check when a
// lookup fails for a transport or server reason. A missing, legacy or
// malformed snapshot is not retried remotely: the SDK rejects it as an invalid
// snapshot, so this service denies instead of allowing.
func NewAuthorizer(o Options) (*Authorizer, error) {
	base := strings.TrimRight(strings.TrimSpace(o.BaseURL), "/")
	if base == "" {
		return nil, errors.New("iam: base URL is required")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("iam: invalid base URL %q", o.BaseURL)
	}

	logger := o.Logger
	if logger == nil {
		logger = discardLogger()
	}
	httpClient := o.resolveHTTPClient()
	source := serviceTokenSource(o, httpClient)

	permissionOptions := []any{iam.WithHTTPClient(httpClient)}
	if source != nil {
		permissionOptions = append(permissionOptions, iam.WithTokenSource(source))
	}

	verifier := iam.NewVerifier(
		base,
		iam.WithIssuer(o.Issuer),
		iam.WithAudience(o.Audience),
		iam.WithHTTPClient(httpClient),
	)
	permissions := iam.NewPermissionsClient(base, permissionOptions...)
	client := iam.NewClient(verifier, permissions)

	authorizer := &Authorizer{
		client:      client,
		verifier:    verifier,
		permissions: permissions,
		log:         logger,
		httpClient:  httpClient,
		baseURL:     base,
	}
	authorizer.allow = client.Allow
	for _, warning := range o.Warnings() {
		logger.Warn("iam: configuration warning", "warning", warning)
	}
	if natsURL := strings.TrimSpace(o.NATSURL); natsURL != "" {
		authorizer.subscribeInvalidationEvents(natsURL)
	}
	return authorizer, nil
}

// subscribeInvalidationEvents wires optional cache invalidation. NATS support
// is compiled into the SDK with the nats build tag; without it the SDK reports
// that support is disabled, which downgrades to a warning because the caches
// still expire on their own TTL.
func (a *Authorizer) subscribeInvalidationEvents(natsURL string) {
	permissionSubscription, err := a.permissions.SubscribePermissions(natsURL, func(userIDs []string) {
		a.log.Debug("iam: permission cache invalidated by event", "users", len(userIDs))
	})
	if err != nil {
		a.log.Warn("iam: permission invalidation events are disabled", "error", err.Error())
	} else if permissionSubscription != nil {
		a.subscriptions = append(a.subscriptions, permissionSubscription)
	}

	keySubscription, err := a.verifier.SubscribeKeyRotations(natsURL)
	if err != nil {
		a.log.Warn("iam: JWKS key-rotation events are disabled", "error", err.Error())
	} else if keySubscription != nil {
		a.subscriptions = append(a.subscriptions, keySubscription)
	}
}

// Close releases event subscriptions and the JWKS cache background workers.
func (a *Authorizer) Close() {
	if a == nil {
		return
	}
	for _, subscription := range a.subscriptions {
		_ = subscription.Close()
	}
	a.subscriptions = nil
	if a.verifier != nil {
		_ = a.verifier.Close()
	}
}

// Authenticate verifies the request bearer token and stores the resulting
// claims in the request context. Failures are answered with the RFC 9457
// problem document used by teamusers: title Unauthorized, detail invalid_token.
func (a *Authorizer) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeUnauthorized(w, r, "invalid_token")
			return
		}
		if a == nil || a.verifier == nil {
			a.logVerificationFailure(r, "authorizer is not configured")
			writeUnauthorized(w, r, "invalid_token")
			return
		}
		claims, err := a.verifier.Verify(r.Context(), token)
		if err != nil {
			a.logVerificationFailure(r, redactSecret(err.Error(), token))
			writeUnauthorized(w, r, "invalid_token")
			return
		}
		// The verifier only accepts the "user" and "service" subject kinds, so
		// no additional kind check is required here; every other kind already
		// failed verification.
		next.ServeHTTP(w, r.WithContext(iam.WithClaims(r.Context(), claims)))
	})
}

// Claims returns the verified claims stored by Authenticate.
func (a *Authorizer) Claims(r *http.Request) (iam.Claims, bool) {
	if r == nil {
		return iam.Claims{}, false
	}
	return iam.ClaimsFromContext(r.Context())
}

// Decide authorizes one request for the given claims.
//
// Scopes are evaluated broadest first: any, then team (only when the resource
// belongs to a team), then own (only when the subject owns the resource). The
// first allow wins, an explicit deny is terminal, and an exhausted cascade
// denies. The returned reason is intended for the 403 problem document and
// lists the attempted keys; it never contains credential material.
//
// Decide is fail-closed and never returns an error: the SDK folds transport
// and cache failures into a denial reason.
func (a *Authorizer) Decide(ctx context.Context, claims iam.Claims, verb string, res iam.Resource) (bool, string, error) {
	if a == nil || a.allow == nil {
		return false, "authorization unavailable", errAuthorizerUnavailable
	}
	action, err := normalizeVerb(verb)
	if err != nil {
		return false, err.Error(), err
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return false, "subject is missing", nil
	}
	allowed, reason := a.cascade(ctx, claims, action, res)
	return allowed, reason, nil
}

// DecideSubject authorizes a presigned-URL redemption for a subject that was
// embedded in the token signature rather than in a live access token.
//
// The subject's effective permissions are fetched first (or served from cache)
// and compared with the permission version carried by the signature; a
// mismatch means the permissions changed after the URL was minted, so the
// redemption is denied with reason "permissions changed". Only then does the
// ordinary scope cascade run.
func (a *Authorizer) DecideSubject(ctx context.Context, subject, kind, team string, permVer int64, verb string, res iam.Resource) (bool, string, error) {
	if a == nil || a.permissions == nil || a.allow == nil {
		return false, "authorization unavailable", errAuthorizerUnavailable
	}
	action, err := normalizeVerb(verb)
	if err != nil {
		return false, err.Error(), err
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return false, "subject is missing", nil
	}

	entry, err := a.permissions.Get(ctx, subject, permVer)
	if err != nil {
		return false, "authorization service unavailable", fmt.Errorf("iam: fetch permissions for presigned subject: %w", err)
	}
	if entry == nil || entry.PermVer != permVer {
		return false, "permissions changed", nil
	}

	claims := iam.Claims{Subject: subject, Kind: kind, Team: team, PermVer: permVer}
	allowed, reason := a.cascade(ctx, claims, action, res)
	return allowed, reason, nil
}

// Grants returns the caller's effective grants, including deny keys (entries
// with Permission.Deny set), which callers must honour when filtering lists.
//
// A cached entry is only reused while its perm_ver matches the token, so the
// result reflects the authoritative permission set after a change. Grants that
// carry an ABAC condition, and grants scoped to one team (Grant.TeamID), are
// returned as plain permission keys without that qualifier; consumers that must
// not over-authorize should re-check the specific request with Decide.
func (a *Authorizer) Grants(ctx context.Context, claims iam.Claims) ([]iam.Permission, error) {
	if a == nil || a.permissions == nil {
		return nil, errAuthorizerUnavailable
	}
	subject := strings.TrimSpace(claims.Subject)
	if subject == "" {
		return nil, errors.New("iam: claims subject is missing")
	}
	entry, err := a.permissions.Get(ctx, subject, claims.PermVer)
	if err != nil {
		return nil, fmt.Errorf("iam: fetch permissions: %w", err)
	}
	if entry == nil {
		return nil, errors.New("iam: permissions client returned no entry")
	}
	grants := make([]iam.Permission, 0, len(entry.Grants))
	for _, grant := range entry.Grants {
		permission, parseErr := iam.Parse(grant.Key)
		if parseErr != nil {
			continue
		}
		grants = append(grants, permission)
	}
	return grants, nil
}

// Healthy reports whether the teamusers JWKS document is reachable. It is used
// by the doctor subcommand and is not part of the request path.
func (a *Authorizer) Healthy(ctx context.Context) error {
	if a == nil || a.httpClient == nil || a.baseURL == "" {
		return errAuthorizerUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return fmt.Errorf("iam: create JWKS request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := a.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("iam: fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("iam: JWKS endpoint answered %s", response.Status)
	}
	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJWKSBytes)).Decode(&document); err != nil {
		return fmt.Errorf("iam: decode JWKS: %w", err)
	}
	if len(document.Keys) == 0 {
		return errors.New("iam: JWKS document contains no keys")
	}
	return nil
}

// cascade runs the scope cascade and produces the denial reason.
func (a *Authorizer) cascade(ctx context.Context, claims iam.Claims, verb string, res iam.Resource) (bool, string) {
	keys := cascadeKeys(verb, res, claims.Subject)
	attempted := make([]string, 0, len(keys))
	lastReason := ""
	for _, key := range keys {
		attempted = append(attempted, key)
		allowed, reason := a.allow(ctx, claims, key, res)
		if allowed {
			return true, "allowed by " + key
		}
		if reason == policyDeniedReason {
			return false, "denied by " + key
		}
		if reason != "" {
			lastReason = reason
		}
	}
	summary := "no matching grant for " + strings.Join(attempted, ", ")
	if lastReason != "" {
		summary += " (" + lastReason + ")"
	}
	return false, summary
}

// cascadeKeys returns the permission keys to attempt, broadest scope first.
func cascadeKeys(verb string, res iam.Resource, subject string) []string {
	keys := make([]string, 0, 3)
	keys = append(keys, resourceSegment+":"+verb+":any")
	if res.TeamID != "" {
		keys = append(keys, resourceSegment+":"+verb+":team")
	}
	if subject != "" && res.OwnerID == subject {
		keys = append(keys, resourceSegment+":"+verb+":own")
	}
	return keys
}

// normalizeVerb validates the permission action used to build cascade keys.
func normalizeVerb(verb string) (string, error) {
	verb = strings.ToLower(strings.TrimSpace(verb))
	if _, ok := verbActions[verb]; !ok {
		return "", fmt.Errorf("iam: unsupported permission verb %q", verb)
	}
	return verb, nil
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// writeUnauthorized answers an unauthenticated or unverifiable request with the
// problem document shared by the whole service: type about:blank, title
// Unauthorized, detail invalid_token.
//
// The instance is the request id the httpx request-id middleware installs in
// the request context. Because the middleware is owned by another layer, the
// identifier is also read back from the X-Request-Id response header when the
// context carries none, so the document reports the id with either mechanism.
// The inbound request header is deliberately not consulted: it is client
// controlled and would let a caller choose the reported instance. When no
// request-id middleware is installed the field is omitted.
func writeUnauthorized(w http.ResponseWriter, r *http.Request, detail string) {
	if r != nil && httpx.RequestIDFromContext(r) == "" {
		if id := strings.TrimSpace(w.Header().Get(httpx.HeaderRequestID)); id != "" {
			r = r.WithContext(httpx.WithRequestID(r.Context(), id))
		}
	}
	httpx.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", detail)
}

// logVerificationFailure logs a verification failure after removing the raw
// token, so credential material can never reach the log.
func (a *Authorizer) logVerificationFailure(r *http.Request, message string) {
	if a == nil || a.log == nil {
		return
	}
	a.log.WarnContext(r.Context(), "iam: access token rejected", "error", message)
}

// redactSecret replaces the secret with a placeholder if a message contains it.
func redactSecret(message, secret string) string {
	if secret == "" {
		return message
	}
	return strings.ReplaceAll(message, secret, "[redacted]")
}

// discardLogger returns a logger that drops every record.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
